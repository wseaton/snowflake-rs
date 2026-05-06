use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),

    #[error(transparent)]
    RequestMiddlewareError(#[from] reqwest_middleware::Error),

    #[error(transparent)]
    UrlParsing(#[from] url::ParseError),

    #[error(transparent)]
    Deserialization(#[from] serde_json::Error),

    #[error(transparent)]
    InvalidHeader(#[from] header::InvalidHeaderValue),
}

/// Container for query parameters
/// This API has different endpoints and MIME types for different requests
struct QueryContext {
    path: Cow<'static, str>,
    accept_mime: &'static str,
    method: Method,
}

pub enum QueryType {
    LoginRequest,
    AuthenticatorRequest,
    TokenRequest,
    CloseSession,
    JsonQuery,
    ArrowQuery,
    /// GET /queries/<id>/result. Used to poll the result of a query that
    /// Snowflake decided to run async (response code 333334). The contained
    /// path is the `getResultUrl` from the original async response.
    ArrowQueryResult(String),
    /// POST /queries/v1/abort-request. Cancels an in-flight query identified
    /// by the original query's `request_id` (carried in the body, not the path).
    AbortRequest,
    /// POST /session/heartbeat. Keeps the session token alive when the
    /// caller opted into `client_session_keep_alive` on the builder. Body
    /// is empty; auth is the current session token.
    Heartbeat,
}

impl QueryType {
    fn query_context(&self) -> QueryContext {
        match self {
            Self::LoginRequest => QueryContext {
                path: Cow::Borrowed("session/v1/login-request"),
                accept_mime: "application/json",
                method: Method::POST,
            },
            Self::AuthenticatorRequest => QueryContext {
                path: Cow::Borrowed("session/authenticator-request"),
                accept_mime: "application/json",
                method: Method::POST,
            },
            Self::TokenRequest => QueryContext {
                path: Cow::Borrowed("/session/token-request"),
                accept_mime: "application/snowflake",
                method: Method::POST,
            },
            Self::CloseSession => QueryContext {
                path: Cow::Borrowed("session"),
                accept_mime: "application/snowflake",
                method: Method::POST,
            },
            Self::JsonQuery => QueryContext {
                path: Cow::Borrowed("queries/v1/query-request"),
                accept_mime: "application/json",
                method: Method::POST,
            },
            Self::ArrowQuery => QueryContext {
                path: Cow::Borrowed("queries/v1/query-request"),
                accept_mime: "application/snowflake",
                method: Method::POST,
            },
            Self::ArrowQueryResult(get_result_url) => QueryContext {
                // get_result_url comes back as an absolute path like
                // `/queries/<id>/result`. Strip the leading slash so it joins
                // cleanly with our base host URL builder below.
                path: Cow::Owned(get_result_url.trim_start_matches('/').to_owned()),
                accept_mime: "application/snowflake",
                method: Method::GET,
            },
            Self::AbortRequest => QueryContext {
                path: Cow::Borrowed("queries/v1/abort-request"),
                accept_mime: "application/snowflake",
                method: Method::POST,
            },
            Self::Heartbeat => QueryContext {
                path: Cow::Borrowed("session/heartbeat"),
                accept_mime: "application/snowflake",
                method: Method::POST,
            },
        }
    }
}

/// Per-request identifiers Snowflake uses for retry/cancel correlation.
/// Lifted out of `Connection::request` so the exec path can stash the
/// `request_id` for later abort.
#[derive(Clone, Copy, Debug)]
pub struct RequestParams {
    pub request_id: Uuid,
    pub request_guid: Uuid,
}

impl RequestParams {
    pub fn new() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            request_guid: Uuid::new_v4(),
        }
    }

    /// Build with an optional pre-chosen `request_id`. `None` => fresh.
    pub fn or_new(request_id: Option<Uuid>) -> Self {
        match request_id {
            Some(id) => Self {
                request_id: id,
                request_guid: Uuid::new_v4(),
            },
            None => Self::new(),
        }
    }
}

impl Default for RequestParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection pool
/// Minimal session will have at least 2 requests - login and query
pub struct Connection {
    // no need for Arc as it's already inside the reqwest client
    client: ClientWithMiddleware,
}

impl Connection {
    pub fn new() -> Result<Self, ConnectionError> {
        let client = Self::default_client_builder()?;

        Ok(Self::new_with_middware(client.build()))
    }

    /// Allow a user to provide their own middleware
    ///
    /// Users can provide their own middleware to the connection like this:
    /// ```rust
    /// use snowflake_api::connection::Connection;
    /// let mut client = Connection::default_client_builder();
    ///  // modify the client builder here
    /// let connection = Connection::new_with_middware(client.unwrap().build());
    /// ```
    /// This is not intended to be called directly, but is used by `SnowflakeApiBuilder::with_client`
    pub fn new_with_middware(client: ClientWithMiddleware) -> Self {
        Self { client }
    }

    pub fn default_client_builder() -> Result<reqwest_middleware::ClientBuilder, ConnectionError> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);

        let client = reqwest::ClientBuilder::new()
            .user_agent("Rust/0.0.1")
            .gzip(true)
            .referer(false);

        #[cfg(debug_assertions)]
        let client = client.connection_verbose(true);

        let client = client.build()?;

        Ok(reqwest_middleware::ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy)))
    }

    /// Perform request of given query type with extra body or parameters.
    ///
    /// `params` carries the `requestId` and `request_guid` URL params. Callers
    /// that may later need to cancel (the query exec path) should generate
    /// these via `RequestParams::new()` and hold the `request_id`. Callers
    /// that don't care can pass `None` and we'll generate fresh ids per call.
    // todo: implement soft error handling
    // todo: is there better way to not repeat myself?
    pub async fn request<R: serde::de::DeserializeOwned>(
        &self,
        query_type: QueryType,
        account_identifier: &str,
        extra_get_params: &[(&str, &str)],
        auth: Option<&str>,
        body: impl serde::Serialize,
        params: Option<RequestParams>,
    ) -> Result<R, ConnectionError> {
        let context = query_type.query_context();

        let params = params.unwrap_or_default();
        let client_start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        let request_id = params.request_id.to_string();
        let request_guid = params.request_guid.to_string();

        let mut get_params = vec![
            ("clientStartTime", client_start_time.as_str()),
            ("requestId", request_id.as_str()),
            ("request_guid", request_guid.as_str()),
        ];
        get_params.extend_from_slice(extra_get_params);

        let url = format!(
            "https://{}.snowflakecomputing.com/{}",
            &account_identifier, context.path
        );
        let url = Url::parse_with_params(&url, get_params)?;

        let mut headers = HeaderMap::new();
        headers.append(
            header::ACCEPT,
            HeaderValue::from_static(context.accept_mime),
        );
        if let Some(auth) = auth {
            let mut auth_val = HeaderValue::from_str(auth)?;
            auth_val.set_sensitive(true);
            headers.append(header::AUTHORIZATION, auth_val);
        }

        // todo: persist client to use connection polling
        let resp = match context.method {
            Method::GET => self.client.get(url).headers(headers).send().await?,
            // POST is the default; treat anything else as POST since we don't
            // currently model PUT/DELETE/etc on this internal endpoint.
            _ => {
                self.client
                    .post(url)
                    .headers(headers)
                    .json(&body)
                    .send()
                    .await?
            }
        };

        let bytes = resp.bytes().await?;
        match serde_json::from_slice::<R>(&bytes) {
            Ok(parsed) => Ok(parsed),
            Err(e) => {
                log::debug!(
                    "Failed to deserialize response body: {} | body: {}",
                    e,
                    String::from_utf8_lossy(&bytes)
                );
                Err(e.into())
            }
        }
    }

    pub async fn get_chunk(
        &self,
        url: &str,
        headers: &HashMap<String, String>,
    ) -> Result<bytes::Bytes, ConnectionError> {
        let mut header_map = HeaderMap::new();
        for (k, v) in headers {
            header_map.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_bytes(v.as_bytes()).unwrap(),
            );
        }
        let bytes = self
            .client
            .get(url)
            .headers(header_map)
            .send()
            .await?
            .bytes()
            .await?;
        Ok(bytes)
    }
}
