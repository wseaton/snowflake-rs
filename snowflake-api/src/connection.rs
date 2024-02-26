use http::uri::Scheme;
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use std::collections::HashMap;
use thiserror::Error;
use url::Url;

use crate::middleware::UuidMiddleware;

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
    path: &'static str,
    accept_mime: &'static str,
}

pub enum QueryType {
    LoginRequest,
    TokenRequest,
    CloseSession,
    JsonQuery,
    ArrowQuery,
}

impl QueryType {
    const fn query_context(&self) -> QueryContext {
        match self {
            Self::LoginRequest => QueryContext {
                path: "session/v1/login-request",
                accept_mime: "application/json",
            },
            Self::TokenRequest => QueryContext {
                path: "/session/token-request",
                accept_mime: "application/snowflake",
            },
            Self::CloseSession => QueryContext {
                path: "session",
                accept_mime: "application/snowflake",
            },
            Self::JsonQuery => QueryContext {
                path: "queries/v1/query-request",
                accept_mime: "application/json",
            },
            Self::ArrowQuery => QueryContext {
                path: "queries/v1/query-request",
                accept_mime: "application/snowflake",
            },
        }
    }
}

/// Connection pool
/// Minimal session will have at least 2 requests - login and query
pub struct Connection {
    // no need for Arc as it's already inside the reqwest client
    client: ClientWithMiddleware,
    base_url: String,
    scheme: http::uri::Scheme,
}

impl Connection {
    pub fn new() -> Result<Self, ConnectionError> {
        let client = Self::default_client_builder()?;

        Ok(Self::new_with_middware(
            client.build(),
            None,
            Some(http::uri::Scheme::HTTPS),
        ))
    }

    /// Allow a user to provide their own middleware
    ///
    /// Users can provide their own middleware to the connection like this:
    /// ```rust
    /// use snowflake_api::connection::Connection;
    /// let mut client = Connection::default_client_builder();
    ///  // modify the client builder here
    /// let connection = Connection::new_with_middware(client.unwrap().build(), None, Some(http::uri::Scheme::HTTPS));
    /// ```
    /// This is not intended to be called directly, but is used by `SnowflakeApiBuilder::with_client`
    pub fn new_with_middware(
        client: ClientWithMiddleware,
        base_url: Option<String>,
        scheme: Option<Scheme>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.unwrap_or(".snowflakecomputing.com".to_string()),
            scheme: scheme.unwrap_or(Scheme::HTTPS),
        }
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
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .with(UuidMiddleware))
    }

    /// Perform request of given query type with extra body or parameters
    // todo: implement soft error handling
    // todo: is there better way to not repeat myself?
    pub async fn request<R: serde::de::DeserializeOwned>(
        &self,
        query_type: QueryType,
        account_identifier: &str,
        extra_get_params: &[(&str, &str)],
        auth: Option<&str>,
        body: impl serde::Serialize,
    ) -> Result<R, ConnectionError> {
        let context = query_type.query_context();

        let mut get_params = vec![];
        get_params.extend_from_slice(extra_get_params);

        let url = format!(
            "{}://{}{}/{}",
            self.scheme, &account_identifier, self.base_url, context.path
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
        let resp = self
            .client
            .post(url)
            .headers(headers)
            .json(&body)
            .send()
            .await?;

        Ok(resp.json::<R>().await?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::uri::Scheme;
    use serde_json::json;
    use uuid::Uuid;
    use dashmap::DashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_request() {
        tracing_subscriber::fmt::init();

        let opts = mockito::ServerOpts {
            host: "0.0.0.0",
            port: 1234,
            ..Default::default()
        };

        let client = Connection::default_client_builder();
        let conn = Connection::new_with_middware(
            client.unwrap().build(),
            Some("0.0.0.0:1234".to_string()),
            Some(Scheme::HTTP),
        );

        let mut server = mockito::Server::new_with_opts_async(opts).await;

        let ctx = QueryType::LoginRequest.query_context();

        // using a dashmap to capture the requestIds across
        //all requests to our mock server
        let mut request_ids = Arc::new(DashMap::new());
        let request_ids_clone = Arc::clone(&request_ids);

        let _m1 = server
            .mock("POST", "/session/v1/login-request")
            .match_query(mockito::Matcher::Any)
            // force an error to validate retries
            .with_status(500)
            .with_header("content-type", ctx.accept_mime)
            // mechanism to validate the request body (feed it back to the client)
            .with_body_from_request(move |request| {

                let path_and_query = request.path_and_query();
                let binding = String::new();
                let query = path_and_query.split('?').nth(1).unwrap_or(&binding);
                let params: HashMap<String, String> =
                    serde_urlencoded::from_str(query).unwrap_or_else(|_| HashMap::new());

                let another_binding = String::new();
                let request_id = params.get("requestId").unwrap_or(&another_binding);

                request_ids_clone.insert(request_id.clone(), true);

                let body = json!({"error": "an error happened", "requestId": request_id});
                body.to_string().as_bytes().to_vec()
            })
            .expect(4)
            .create_async()
            .await;

        match conn
            .request::<serde_json::Value>(
                QueryType::LoginRequest,
                "",
                &[],
                None,
                json!({"query": "SELECT 1"}),
            )
            .await
        {
            Ok(res) => {
                assert_eq!(res["error"], "an error happened");

                // assert that the requestId is present and is a valid UUID
                let request_id = res["requestId"].as_str().unwrap();
                assert_eq!(Uuid::parse_str(request_id).is_ok(), true);

            }
            Err(e) => {
                log::error!("Error: {}", e);
            }
        };


        // assert that all requests were made with different requestIds
        assert_eq!(request_ids.len(), 4);

        request_ids.iter().for_each(|entry| {
            let request_id = entry.key();
            log::info!("Captured Request ID: {}", request_id);
            assert_eq!(Uuid::parse_str(request_id).is_ok(), true);
        });

        _m1.assert_async().await;
    }
}
