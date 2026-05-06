#![doc(
    issue_tracker_base_url = "https://github.com/mycelial/snowflake-rs/issues",
    test(no_crate_inject)
)]
#![doc = include_str!("../README.md")]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
clippy::must_use_candidate,
clippy::missing_errors_doc,
clippy::module_name_repetitions,
clippy::struct_field_names,
clippy::future_not_send, // This one seems like something we should eventually fix
clippy::missing_panics_doc
)]

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use arrow_ipc::reader::StreamReader;
use base64::Engine;
use bytes::{Buf, Bytes};
use futures::future::try_join_all;
use futures::stream::{self, BoxStream, StreamExt};
use regex::Regex;
use reqwest_middleware::ClientWithMiddleware;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// Part of public interface
pub use arrow_array::RecordBatch;
pub use arrow_schema::ArrowError;

pub use crate::responses::SnowflakeType;

use responses::ExecResponse;
use session::{AuthError, Session};

use crate::connection::QueryType;
use crate::connection::{Connection, ConnectionError, RequestParams};
pub use crate::requests::Bind;

use crate::requests::{AbortRequest, ExecRequest};
use crate::responses::{
    is_query_in_progress, is_query_not_executing, is_session_expired, is_sql_execution_cancelled,
    CancelQueryResponse, ExecResponseRowType,
};
use crate::session::AuthError::MissingEnvArgument;

#[cfg(feature = "browser-auth")]
mod browser;
pub mod connection;
#[cfg(feature = "polars")]
mod polars;
mod put;
mod requests;
mod responses;
mod session;

#[derive(Error, Debug)]
pub enum SnowflakeApiError {
    #[error(transparent)]
    RequestError(#[from] ConnectionError),

    #[error(transparent)]
    AuthError(#[from] AuthError),

    #[error(transparent)]
    ResponseDeserializationError(#[from] base64::DecodeError),

    #[error(transparent)]
    ArrowError(#[from] ArrowError),

    #[error("S3 bucket path in PUT request is invalid: `{0}`")]
    InvalidBucketPath(String),

    #[error("Couldn't extract filename from the local path: `{0}`")]
    InvalidLocalPath(String),

    #[error(transparent)]
    LocalIoError(#[from] io::Error),

    #[error(transparent)]
    ObjectStoreError(#[from] object_store::Error),

    #[error(transparent)]
    ObjectStorePathError(#[from] object_store::path::Error),

    #[error(transparent)]
    TokioTaskJoinError(#[from] tokio::task::JoinError),

    #[error("Snowflake API error. Code: `{0}`. Message: `{1}`")]
    ApiError(String, String),

    #[error("Snowflake API empty response could mean that query wasn't executed correctly or API call was faulty")]
    EmptyResponse,

    #[error("No usable rowsets were included in the response")]
    BrokenResponse,

    #[error("Following feature is not implemented yet: {0}")]
    Unimplemented(String),

    #[error("Unexpected API response")]
    UnexpectedResponse,

    #[error("Query was cancelled by the caller")]
    QueryCancelled,

    #[error("Streaming is only supported for Arrow responses; got JSON. Use execute()/execute_raw() instead.")]
    JsonStreamUnsupported,

    #[error(transparent)]
    GlobPatternError(#[from] glob::PatternError),

    #[error(transparent)]
    GlobError(#[from] glob::GlobError),
}

/// Even if Arrow is specified as a return type non-select queries
/// will return Json array of arrays: `[[42, "answer"], [43, "non-answer"]]`.
pub struct JsonResult {
    // todo: can it _only_ be a json array of arrays or something else too?
    pub value: serde_json::Value,
    /// Field ordering matches the array ordering
    pub schema: Vec<FieldSchema>,
}

impl Display for JsonResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Based on the [`ExecResponseRowType`]
pub struct FieldSchema {
    pub name: String,
    // todo: is it a good idea to expose internal response struct to the user?
    pub type_: SnowflakeType,
    pub scale: Option<i64>,
    pub precision: Option<i64>,
    pub nullable: bool,
}

impl From<ExecResponseRowType> for FieldSchema {
    fn from(value: ExecResponseRowType) -> Self {
        FieldSchema {
            name: value.name,
            type_: value.type_,
            scale: value.scale,
            precision: value.precision,
            nullable: value.nullable,
        }
    }
}

/// Container for query result.
/// Arrow is returned by-default for all SELECT statements,
/// unless there is session configuration issue or it's a different statement type.
pub enum QueryResult {
    Arrow(Vec<RecordBatch>),
    Json(JsonResult),
    Empty,
}

/// Raw query result
/// Can be transformed into [`QueryResult`]
pub enum RawQueryResult {
    /// Arrow IPC chunks
    /// see: <https://arrow.apache.org/docs/format/Columnar.html#serialization-and-interprocess-communication-ipc>
    Bytes(Vec<Bytes>),
    /// Json payload is deserialized,
    /// as it's already a part of REST response
    Json(JsonResult),
    Empty,
}

/// Stream of Arrow IPC blobs, one per Snowflake chunk, in original response
/// order. Suitable for forwarding through HTTP/SSE without re-encoding.
pub type ArrowChunkStream = BoxStream<'static, Result<Bytes, SnowflakeApiError>>;

/// Stream of decoded Arrow `RecordBatch`es. A single Snowflake chunk may
/// contain multiple batches; they are flattened into the stream in order.
pub type RecordBatchStream = BoxStream<'static, Result<RecordBatch, SnowflakeApiError>>;

/// Matches Snowflake's default `CLIENT_PREFETCH_THREADS` and gosnowflake /
/// JDBC defaults. Caps in-flight downloads while preserving order via
/// `StreamExt::buffered`.
const DEFAULT_PREFETCH_CHUNKS: usize = 4;

enum ResolvedArrowResult {
    Empty,
    Json(JsonResult),
    Chunked {
        inline_base64: Option<String>,
        chunks: Vec<crate::responses::ExecResponseChunk>,
        chunk_headers: HashMap<String, String>,
    },
}

fn build_arrow_chunk_stream(
    connection: Arc<Connection>,
    inline_base64: Option<String>,
    chunks: Vec<crate::responses::ExecResponseChunk>,
    chunk_headers: HashMap<String, String>,
) -> ArrowChunkStream {
    let inline = stream::iter(inline_base64.into_iter().map(|b64| {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map(Bytes::from)
            .map_err(SnowflakeApiError::from)
    }));

    let headers = Arc::new(chunk_headers);
    let external = stream::iter(chunks)
        .map(move |chunk| {
            let connection = Arc::clone(&connection);
            let headers = Arc::clone(&headers);
            async move {
                connection
                    .get_chunk(&chunk.url, &headers)
                    .await
                    .map_err(SnowflakeApiError::from)
            }
        })
        .buffered(DEFAULT_PREFETCH_CHUNKS);

    inline.chain(external).boxed()
}

fn build_record_batch_stream(raw: ArrowChunkStream) -> RecordBatchStream {
    raw.flat_map(|item| match item {
        Err(e) => stream::iter(vec![Err(e)]).boxed(),
        Ok(bytes) => match StreamReader::try_new(bytes.reader(), None) {
            Err(e) => stream::iter(vec![Err(SnowflakeApiError::from(e))]).boxed(),
            Ok(reader) => stream::iter(
                reader
                    .map(|r| r.map_err(SnowflakeApiError::from))
                    .collect::<Vec<_>>(),
            )
            .boxed(),
        },
    })
    .boxed()
}

impl RawQueryResult {
    pub fn deserialize_arrow(self) -> Result<QueryResult, ArrowError> {
        match self {
            RawQueryResult::Bytes(bytes) => {
                Self::flat_bytes_to_batches(bytes).map(QueryResult::Arrow)
            }
            RawQueryResult::Json(j) => Ok(QueryResult::Json(j)),
            RawQueryResult::Empty => Ok(QueryResult::Empty),
        }
    }

    fn flat_bytes_to_batches(bytes: Vec<Bytes>) -> Result<Vec<RecordBatch>, ArrowError> {
        let mut res = vec![];
        for b in bytes {
            let mut batches = Self::bytes_to_batches(b)?;
            res.append(&mut batches);
        }
        Ok(res)
    }

    fn bytes_to_batches(bytes: Bytes) -> Result<Vec<RecordBatch>, ArrowError> {
        let record_batches = StreamReader::try_new(bytes.reader(), None)?;
        record_batches.into_iter().collect()
    }
}

pub struct AuthArgs {
    pub account_identifier: String,
    pub warehouse: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub username: String,
    pub role: Option<String>,
    pub auth_type: AuthType,
}

impl AuthArgs {
    pub fn from_env() -> Result<AuthArgs, SnowflakeApiError> {
        let authenticator = std::env::var("SNOWFLAKE_AUTHENTICATOR")
            .ok()
            .map(|s| s.to_lowercase());

        let auth_type = match authenticator.as_deref() {
            #[cfg(feature = "browser-auth")]
            Some("externalbrowser") => Ok(AuthType::ExternalBrowser),
            _ => {
                // Fall back to password or certificate auth
                if let Ok(password) = std::env::var("SNOWFLAKE_PASSWORD") {
                    Ok(AuthType::Password(PasswordArgs { password }))
                } else if let Ok(private_key_pem) = std::env::var("SNOWFLAKE_PRIVATE_KEY") {
                    Ok(AuthType::Certificate(CertificateArgs { private_key_pem }))
                } else {
                    #[cfg(feature = "browser-auth")]
                    {
                        Err(MissingEnvArgument(
                            "SNOWFLAKE_PASSWORD, SNOWFLAKE_PRIVATE_KEY, or SNOWFLAKE_AUTHENTICATOR=externalbrowser".to_owned(),
                        ))
                    }
                    #[cfg(not(feature = "browser-auth"))]
                    {
                        Err(MissingEnvArgument(
                            "SNOWFLAKE_PASSWORD or SNOWFLAKE_PRIVATE_KEY".to_owned(),
                        ))
                    }
                }
            }
        };

        Ok(AuthArgs {
            account_identifier: std::env::var("SNOWFLAKE_ACCOUNT")
                .map_err(|_| MissingEnvArgument("SNOWFLAKE_ACCOUNT".to_owned()))?,
            warehouse: std::env::var("SNOWLFLAKE_WAREHOUSE").ok(),
            database: std::env::var("SNOWFLAKE_DATABASE").ok(),
            schema: std::env::var("SNOWFLAKE_SCHEMA").ok(),
            username: std::env::var("SNOWFLAKE_USER")
                .map_err(|_| MissingEnvArgument("SNOWFLAKE_USER".to_owned()))?,
            role: std::env::var("SNOWFLAKE_ROLE").ok(),
            auth_type: auth_type?,
        })
    }
}

pub enum AuthType {
    Password(PasswordArgs),
    Certificate(CertificateArgs),
    #[cfg(feature = "browser-auth")]
    ExternalBrowser,
}

pub struct PasswordArgs {
    pub password: String,
}

pub struct CertificateArgs {
    pub private_key_pem: String,
}

#[must_use]
pub struct SnowflakeApiBuilder {
    pub auth: AuthArgs,
    client: Option<ClientWithMiddleware>,
}

impl SnowflakeApiBuilder {
    pub fn new(auth: AuthArgs) -> Self {
        Self { auth, client: None }
    }

    pub fn with_client(mut self, client: ClientWithMiddleware) -> Self {
        self.client = Some(client);
        self
    }

    pub fn build(self) -> Result<SnowflakeApi, SnowflakeApiError> {
        let connection = match self.client {
            Some(client) => Arc::new(Connection::new_with_middware(client)),
            None => Arc::new(Connection::new()?),
        };

        let session = match self.auth.auth_type {
            AuthType::Password(args) => Session::password_auth(
                Arc::clone(&connection),
                &self.auth.account_identifier,
                self.auth.warehouse.as_deref(),
                self.auth.database.as_deref(),
                self.auth.schema.as_deref(),
                &self.auth.username,
                self.auth.role.as_deref(),
                &args.password,
            ),
            AuthType::Certificate(args) => Session::cert_auth(
                Arc::clone(&connection),
                &self.auth.account_identifier,
                self.auth.warehouse.as_deref(),
                self.auth.database.as_deref(),
                self.auth.schema.as_deref(),
                &self.auth.username,
                self.auth.role.as_deref(),
                &args.private_key_pem,
            ),
            #[cfg(feature = "browser-auth")]
            AuthType::ExternalBrowser => Session::browser_auth(
                Arc::clone(&connection),
                &self.auth.account_identifier,
                self.auth.warehouse.as_deref(),
                self.auth.database.as_deref(),
                self.auth.schema.as_deref(),
                &self.auth.username,
                self.auth.role.as_deref(),
            ),
        };

        let account_identifier = self.auth.account_identifier.to_uppercase();

        Ok(SnowflakeApi::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }
}

/// Snowflake API, keeps connection pool and manages session for you
pub struct SnowflakeApi {
    connection: Arc<Connection>,
    session: Session,
    account_identifier: String,
}

impl SnowflakeApi {
    /// Create a new `SnowflakeApi` object with an existing connection and session.
    pub fn new(connection: Arc<Connection>, session: Session, account_identifier: String) -> Self {
        Self {
            connection,
            session,
            account_identifier,
        }
    }
    /// Initialize object with password auth. Authentication happens on the first request.
    pub fn with_password_auth(
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        password: &str,
    ) -> Result<Self, SnowflakeApiError> {
        let connection = Arc::new(Connection::new()?);

        let session = Session::password_auth(
            Arc::clone(&connection),
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            password,
        );

        let account_identifier = account_identifier.to_uppercase();
        Ok(Self::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }

    /// Initialize object with private certificate auth. Authentication happens on the first request.
    pub fn with_certificate_auth(
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        private_key_pem: &str,
    ) -> Result<Self, SnowflakeApiError> {
        let connection = Arc::new(Connection::new()?);

        let session = Session::cert_auth(
            Arc::clone(&connection),
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            private_key_pem,
        );

        let account_identifier = account_identifier.to_uppercase();
        Ok(Self::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }

    /// Initialize object with external browser SSO auth. Authentication happens on the first request.
    ///
    /// This will open a browser window for the user to authenticate via their `IdP`.
    /// Requires the `browser-auth` feature.
    #[cfg(feature = "browser-auth")]
    pub fn with_browser_auth(
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
    ) -> Result<Self, SnowflakeApiError> {
        let connection = Arc::new(Connection::new()?);

        let session = Session::browser_auth(
            Arc::clone(&connection),
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
        );

        let account_identifier = account_identifier.to_uppercase();
        Ok(Self::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }

    pub fn from_env() -> Result<Self, SnowflakeApiError> {
        SnowflakeApiBuilder::new(AuthArgs::from_env()?).build()
    }

    /// Closes the current session, this is necessary to clean up temporary objects (tables, functions, etc)
    /// which are Snowflake session dependent.
    /// If another request is made the new session will be initiated.
    pub async fn close_session(&mut self) -> Result<(), SnowflakeApiError> {
        self.session.close().await?;
        Ok(())
    }

    /// Execute a single query against API.
    /// If statement is PUT, then file will be uploaded to the Snowflake-managed storage
    pub async fn exec(&self, sql: &str) -> Result<QueryResult, SnowflakeApiError> {
        let raw = self.exec_raw(sql).await?;
        let res = raw.deserialize_arrow()?;
        Ok(res)
    }

    /// Executes a single query against API.
    /// If statement is PUT, then file will be uploaded to the Snowflake-managed storage
    /// Returns raw bytes in the Arrow response
    pub async fn exec_raw(&self, sql: &str) -> Result<RawQueryResult, SnowflakeApiError> {
        let put_re = Regex::new(r"(?i)^(?:/\*.*\*/\s*)*put\s+").unwrap();

        // put commands go through a different flow and result is side-effect
        if put_re.is_match(sql) {
            log::info!("Detected PUT query");
            self.exec_put(sql).await.map(|()| RawQueryResult::Empty)
        } else {
            self.exec_arrow_raw(sql).await
        }
    }

    async fn exec_put(&self, sql: &str) -> Result<(), SnowflakeApiError> {
        let (_, resp) = self
            .run_sql::<ExecResponse>(sql, QueryType::JsonQuery)
            .await?;
        log::debug!("Got PUT response: {resp:?}");

        match resp {
            ExecResponse::Query(_) | ExecResponse::QueryAsync(_) => {
                Err(SnowflakeApiError::UnexpectedResponse)
            }
            ExecResponse::PutGet(pg) => put::put(pg).await,
            ExecResponse::Error(e) => Err(SnowflakeApiError::ApiError(
                e.data.error_code,
                e.message.unwrap_or_default(),
            )),
        }
    }

    /// Useful for debugging to get the straight query response
    #[cfg(debug_assertions)]
    pub async fn exec_response(&self, sql: &str) -> Result<ExecResponse, SnowflakeApiError> {
        let (_, resp) = self
            .run_sql::<ExecResponse>(sql, QueryType::ArrowQuery)
            .await?;
        Ok(resp)
    }

    /// Useful for debugging to get raw JSON response
    #[cfg(debug_assertions)]
    pub async fn exec_json(&self, sql: &str) -> Result<serde_json::Value, SnowflakeApiError> {
        let (_, resp) = self
            .run_sql::<serde_json::Value>(sql, QueryType::JsonQuery)
            .await?;
        Ok(resp)
    }

    /// Builder entry point for queries that need bind parameters,
    /// cancellation, or a caller-supplied `request_id`. For unbound,
    /// non-cancellable queries [`SnowflakeApi::exec`] is shorter.
    ///
    /// ```ignore
    /// let r = api.query("SELECT name FROM users WHERE id = ? AND active = ?")
    ///     .bind(123_i64)
    ///     .bind(true)
    ///     .with_cancel(&cancel_token)
    ///     .execute()
    ///     .await?;
    /// ```
    pub fn query<'a>(&'a self, sql: &'a str) -> QueryBuilder<'a> {
        QueryBuilder {
            api: self,
            sql,
            binds: Vec::new(),
            cancel: Cancellation::default(),
            request_id: None,
        }
    }

    /// Execute a query with cooperative cancellation. Cancelling the token
    /// before completion sends a Snowflake `abort-request` for the query and
    /// returns `SnowflakeApiError::QueryCancelled`. Useful for REST APIs
    /// that need to abort Snowflake work when the upstream HTTP request is
    /// cancelled (wire it via `token.clone().drop_guard()` in your handler).
    pub async fn exec_with_cancel(
        &self,
        sql: &str,
        cancel: &CancellationToken,
    ) -> Result<QueryResult, SnowflakeApiError> {
        let raw = self.exec_raw_with_cancel(sql, cancel).await?;
        Ok(raw.deserialize_arrow()?)
    }

    /// Like `exec_raw`, but cooperatively cancellable. See
    /// [`SnowflakeApi::exec_with_cancel`].
    pub async fn exec_raw_with_cancel(
        &self,
        sql: &str,
        cancel: &CancellationToken,
    ) -> Result<RawQueryResult, SnowflakeApiError> {
        self.exec_raw_inner(sql, None, &[], cancel).await
    }

    /// Same as [`SnowflakeApi::exec_with_cancel`], but the caller supplies
    /// the `request_id`. Useful when the cancellation signal lives in a
    /// completely different code path (e.g., a separate HTTP cancel
    /// endpoint that looks up an in-flight query by id) and you want to
    /// pass the id around instead of a `CancellationToken`. The token here
    /// is still honored if you have one; pass a fresh `CancellationToken`
    /// if not.
    pub async fn exec_with_request_id(
        &self,
        sql: &str,
        request_id: Uuid,
        cancel: &CancellationToken,
    ) -> Result<QueryResult, SnowflakeApiError> {
        let raw = self
            .exec_raw_inner(sql, Some(request_id), &[], cancel)
            .await?;
        Ok(raw.deserialize_arrow()?)
    }

    async fn exec_raw_inner(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
    ) -> Result<RawQueryResult, SnowflakeApiError> {
        let put_re = Regex::new(r"(?i)^(?:/\*.*\*/\s*)*put\s+").unwrap();

        if put_re.is_match(sql) {
            // PUT goes through a different non-cancellable flow today. The
            // caller's token can still be respected before the upload starts;
            // once we're streaming to S3 we don't currently abort. PUT
            // statements don't accept bind parameters.
            if cancel.is_cancelled() {
                return Err(SnowflakeApiError::QueryCancelled);
            }
            if !binds.is_empty() {
                return Err(SnowflakeApiError::Unimplemented(
                    "bind parameters on PUT statements".to_owned(),
                ));
            }
            log::info!("Detected PUT query");
            self.exec_put(sql).await.map(|()| RawQueryResult::Empty)
        } else {
            self.exec_arrow_raw_with_cancel(sql, request_id, binds, cancel)
                .await
        }
    }

    /// Cancel a query identified by the `request_id` returned from the
    /// cancellable exec methods or generated by the caller. Idempotent: if
    /// the query has already finished, returns `Ok(())` rather than an
    /// error (matching the Go driver's behavior on `queryNotExecutingCode`).
    pub async fn cancel_query(&self, request_id: Uuid) -> Result<(), SnowflakeApiError> {
        log::debug!("Cancelling query with request_id {request_id}");

        // First attempt.
        let resp = self.send_abort_request(request_id).await?;
        if resp.success || is_query_not_executing(resp.code.as_ref()) {
            return Ok(());
        }

        // If the session expired mid-flight, renew once and retry. We don't
        // implement gosnowflake's full 5-retry session-renewal loop here;
        // one retry covers the common case where the cached token aged out
        // between the original query and the cancel call.
        if is_session_expired(resp.code.as_ref()) {
            log::debug!("Session expired during cancel; renewing and retrying once");
            let _ = self.session.get_token().await?;
            let resp = self.send_abort_request(request_id).await?;
            if resp.success || is_query_not_executing(resp.code.as_ref()) {
                return Ok(());
            }
            return Err(SnowflakeApiError::ApiError(
                resp.code.unwrap_or_default(),
                resp.message.unwrap_or_default(),
            ));
        }

        Err(SnowflakeApiError::ApiError(
            resp.code.unwrap_or_default(),
            resp.message.unwrap_or_default(),
        ))
    }

    async fn send_abort_request(
        &self,
        request_id: Uuid,
    ) -> Result<CancelQueryResponse, SnowflakeApiError> {
        let parts = self.session.get_token().await?;
        let resp = self
            .connection
            .request::<CancelQueryResponse>(
                QueryType::AbortRequest,
                &self.account_identifier,
                &[],
                Some(&parts.session_token_auth_header),
                AbortRequest {
                    request_id: request_id.to_string(),
                },
                // Cancel POST gets its own fresh request_id/request_guid.
                None,
            )
            .await?;
        Ok(resp)
    }

    async fn exec_arrow_raw(&self, sql: &str) -> Result<RawQueryResult, SnowflakeApiError> {
        // Non-cancellable path uses a token that never fires.
        let cancel = CancellationToken::new();
        self.exec_arrow_raw_with_cancel(sql, None, &[], &cancel)
            .await
    }

    async fn exec_arrow_raw_with_cancel(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
    ) -> Result<RawQueryResult, SnowflakeApiError> {
        match self
            .resolve_arrow_query(sql, request_id, binds, cancel)
            .await?
        {
            ResolvedArrowResult::Empty => Ok(RawQueryResult::Empty),
            ResolvedArrowResult::Json(j) => Ok(RawQueryResult::Json(j)),
            ResolvedArrowResult::Chunked {
                inline_base64,
                chunks,
                chunk_headers,
            } => {
                // try_join_all preserves input order, which matches Snowflake's
                // intended chunk ordering (load-bearing for ORDER BY).
                let mut bytes: Vec<Bytes> = try_join_all(
                    chunks
                        .iter()
                        .map(|chunk| self.connection.get_chunk(&chunk.url, &chunk_headers)),
                )
                .await?;

                // Inline base64 is the first page (gosnowflake's `firstBatchRaw`,
                // index 0); external chunks follow.
                if let Some(b64) = inline_base64 {
                    let inline =
                        Bytes::from(base64::engine::general_purpose::STANDARD.decode(b64)?);
                    bytes.insert(0, inline);
                }

                Ok(RawQueryResult::Bytes(bytes))
            }
        }
    }

    async fn resolve_arrow_query(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
    ) -> Result<ResolvedArrowResult, SnowflakeApiError> {
        if cancel.is_cancelled() {
            return Err(SnowflakeApiError::QueryCancelled);
        }

        let params = RequestParams::or_new(request_id);

        let mut resp = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(SnowflakeApiError::QueryCancelled),
            r = self.run_sql_with_params::<ExecResponse>(sql, QueryType::ArrowQuery, params, binds, false) => r?,
        };
        log::debug!("Got query response: {resp:?}");

        // QueryAsync (code 333334) can itself return another QueryAsync; loop
        // until we see a terminal kind.
        while let ExecResponse::QueryAsync(async_data) = resp {
            log::debug!(
                "Got async exec response, polling {} (request_id={})",
                async_data.data.get_result_url,
                params.request_id
            );
            resp = self
                .poll_async_result(&async_data.data.get_result_url, params.request_id, cancel)
                .await?;
        }

        let resp = match resp {
            ExecResponse::Query(qr) => Ok(qr),
            ExecResponse::QueryAsync(_) | ExecResponse::PutGet(_) => {
                Err(SnowflakeApiError::UnexpectedResponse)
            }
            ExecResponse::Error(e) if is_sql_execution_cancelled(e.code.as_ref()) => {
                Err(SnowflakeApiError::QueryCancelled)
            }
            ExecResponse::Error(e) => Err(SnowflakeApiError::ApiError(
                e.data.error_code,
                e.message.unwrap_or_default(),
            )),
        }?;

        if resp.data.returned == 0 {
            Ok(ResolvedArrowResult::Empty)
        } else if let Some(value) = resp.data.rowset {
            // JSON for SELECT only happens when the session is configured for it
            // (debugging path); the default for SELECT is Arrow.
            Ok(ResolvedArrowResult::Json(JsonResult {
                value,
                schema: resp.data.rowtype.into_iter().map(Into::into).collect(),
            }))
        } else if let Some(base64) = resp.data.rowset_base64 {
            Ok(ResolvedArrowResult::Chunked {
                inline_base64: if base64.is_empty() {
                    None
                } else {
                    Some(base64)
                },
                chunks: resp.data.chunks,
                chunk_headers: resp.data.chunk_headers,
            })
        } else {
            Err(SnowflakeApiError::BrokenResponse)
        }
    }

    /// Cancellation governs setup only; once the stream is returned, dropping
    /// it aborts any in-flight chunk downloads.
    async fn exec_arrow_stream(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
    ) -> Result<ArrowChunkStream, SnowflakeApiError> {
        match self
            .resolve_arrow_query(sql, request_id, binds, cancel)
            .await?
        {
            ResolvedArrowResult::Empty => Ok(stream::empty().boxed()),
            ResolvedArrowResult::Json(_) => Err(SnowflakeApiError::JsonStreamUnsupported),
            ResolvedArrowResult::Chunked {
                inline_base64,
                chunks,
                chunk_headers,
            } => Ok(build_arrow_chunk_stream(
                Arc::clone(&self.connection),
                inline_base64,
                chunks,
                chunk_headers,
            )),
        }
    }

    /// Run a SQL statement, generating fresh request params. Returns both
    /// the params and the response so callers in the cancellable exec path
    /// can hold onto `params.request_id` for later abort.
    async fn run_sql<R: serde::de::DeserializeOwned>(
        &self,
        sql_text: &str,
        query_type: QueryType,
    ) -> Result<(RequestParams, R), SnowflakeApiError> {
        let params = RequestParams::new();
        let resp = self
            .run_sql_with_params::<R>(sql_text, query_type, params, &[], false)
            .await?;
        Ok((params, resp))
    }

    /// Run a SQL statement using caller-supplied request params. Used by the
    /// cancellable exec path so the caller controls the `request_id` used
    /// for both the original query and any later abort POST.
    async fn run_sql_with_params<R: serde::de::DeserializeOwned>(
        &self,
        sql_text: &str,
        query_type: QueryType,
        params: RequestParams,
        binds: &[Bind],
        describe_only: bool,
    ) -> Result<R, SnowflakeApiError> {
        log::debug!("Executing: {sql_text}");

        let parts = self.session.get_token().await?;

        // Snowflake's bindings field uses 1-indexed string keys to match `?`
        // placeholder positions in the SQL. Empty -> serialize as omitted.
        let bindings = if binds.is_empty() {
            None
        } else {
            Some(
                binds
                    .iter()
                    .enumerate()
                    .map(|(i, b)| ((i + 1).to_string(), b.0.clone()))
                    .collect(),
            )
        };

        let body = ExecRequest {
            sql_text: sql_text.to_string(),
            async_exec: false,
            sequence_id: parts.sequence_id,
            is_internal: false,
            describe_only,
            bindings,
        };

        let resp = self
            .connection
            .request::<R>(
                query_type,
                &self.account_identifier,
                &[],
                Some(&parts.session_token_auth_header),
                body,
                Some(params),
            )
            .await?;

        Ok(resp)
    }

    /// Poll the `get_result_url` endpoint until Snowflake returns a final
    /// result (or the caller cancels). The endpoint is allowed to itself
    /// return another `QueryAsync`/in-progress body, so we keep going until
    /// we see something else. Backoff matches gosnowflake's
    /// `getQueryResultWithRetriesForAsyncMode`: `[500, 500, 1000, 1500,
    /// 2000, 4000, 5000]ms`, saturating at 5s.
    async fn poll_async_result(
        &self,
        get_result_url: &str,
        request_id: Uuid,
        cancel: &CancellationToken,
    ) -> Result<ExecResponse, SnowflakeApiError> {
        const BACKOFF_MS: &[u64] = &[500, 500, 1000, 1500, 2000, 4000, 5000];
        let mut step: usize = 0;
        let mut renewed = false;

        loop {
            let delay = Duration::from_millis(BACKOFF_MS[step.min(BACKOFF_MS.len() - 1)]);
            tokio::select! {
                biased;
                () = cancel.cancelled() => return self.bail_cancelled(request_id).await,
                () = tokio::time::sleep(delay) => {}
            }
            step = step.saturating_add(1);

            let parts = self.session.get_token().await?;
            let resp = tokio::select! {
                biased;
                () = cancel.cancelled() => return self.bail_cancelled(request_id).await,
                r = self.connection.request::<ExecResponse>(
                    QueryType::ArrowQueryResult(get_result_url.to_owned()),
                    &self.account_identifier,
                    &[],
                    Some(&parts.session_token_auth_header),
                    serde_json::Value::Null,
                    None,
                ) => r?,
            };

            match &resp {
                ExecResponse::QueryAsync(_) => {}
                ExecResponse::Query(qr) if is_query_in_progress(qr.code.as_ref()) => {}
                ExecResponse::Error(e) if is_session_expired(e.code.as_ref()) && !renewed => {
                    log::info!("Session expired mid-poll; renewing and retrying");
                    self.session.force_renew().await?;
                    renewed = true;
                }
                _ => return Ok(resp),
            }
        }
    }

    /// Helper used by the polling loop on cancellation: fire a best-effort
    /// abort and surface `QueryCancelled` to the caller. We log but do not
    /// propagate cancel-side errors — the caller's intent was to abandon
    /// the query, not to learn about the abort endpoint's mood.
    async fn bail_cancelled(&self, request_id: Uuid) -> Result<ExecResponse, SnowflakeApiError> {
        log::debug!("Cancellation observed; sending abort for request_id={request_id}");
        if let Err(e) = self.cancel_query(request_id).await {
            log::warn!("Best-effort cancel failed for request_id={request_id}: {e}");
        }
        Err(SnowflakeApiError::QueryCancelled)
    }
}

/// Fluent builder returned by [`SnowflakeApi::query`]. Accumulates bind
/// parameters and optional cancellation/request-id, then runs the query
/// via `execute()` (deserialized Arrow) or `execute_raw()` (raw bytes).
pub struct QueryBuilder<'a> {
    api: &'a SnowflakeApi,
    sql: &'a str,
    binds: Vec<Bind>,
    cancel: Cancellation<'a>,
    request_id: Option<Uuid>,
}

#[derive(Default)]
enum Cancellation<'a> {
    #[default]
    None,
    Borrowed(&'a CancellationToken),
    OnDrop(CancellationToken, tokio_util::sync::DropGuard),
}

impl<'a> QueryBuilder<'a> {
    /// Append a single positional bind parameter. Order matters: the first
    /// `bind()` matches the first `?` in the SQL.
    #[must_use]
    pub fn bind<B: Into<Bind>>(mut self, value: B) -> Self {
        self.binds.push(value.into());
        self
    }

    /// Append several binds at once. Useful for `iter().map(Into::into)`
    /// patterns when the values come from a heterogeneous source.
    #[must_use]
    pub fn binds<I>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = Bind>,
    {
        self.binds.extend(values);
        self
    }

    /// Wire up cooperative cancellation. See
    /// [`SnowflakeApi::exec_with_cancel`] for the semantics.
    #[must_use]
    pub fn with_cancel(mut self, cancel: &'a CancellationToken) -> Self {
        self.cancel = Cancellation::Borrowed(cancel);
        self
    }

    /// Abort the query on Snowflake if the future returned by `execute()`
    /// / `execute_raw()` is dropped before completion.
    #[must_use]
    pub fn cancel_on_drop(mut self) -> Self {
        let token = CancellationToken::new();
        let guard = token.clone().drop_guard();
        self.cancel = Cancellation::OnDrop(token, guard);
        self
    }

    /// Pre-set the `request_id` so it can be used to cancel the query from
    /// another task via [`SnowflakeApi::cancel_query`].
    #[must_use]
    pub fn request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Run the query and return Arrow-deserialized results.
    pub async fn execute(self) -> Result<QueryResult, SnowflakeApiError> {
        let raw = self.execute_raw().await?;
        Ok(raw.deserialize_arrow()?)
    }

    /// Run the query and return the raw response (Arrow IPC bytes or JSON).
    pub async fn execute_raw(self) -> Result<RawQueryResult, SnowflakeApiError> {
        let owned;
        let _drop_guard;
        let cancel = match self.cancel {
            Cancellation::Borrowed(c) => c,
            Cancellation::OnDrop(token, guard) => {
                owned = token;
                _drop_guard = guard;
                &owned
            }
            Cancellation::None => {
                owned = CancellationToken::new();
                &owned
            }
        };
        self.api
            .exec_raw_inner(self.sql, self.request_id, &self.binds, cancel)
            .await
    }

    /// Run the query and return a stream of decoded `RecordBatch`es. Chunks
    /// are downloaded with bounded prefetch (`DEFAULT_PREFETCH_CHUNKS`) and
    /// yielded in original Snowflake order. The first awaited future
    /// resolves once Snowflake returns the result envelope (including any
    /// async polling); the returned stream then drives the chunk downloads.
    ///
    /// Errors with [`SnowflakeApiError::JsonStreamUnsupported`] if the
    /// response is JSON. Returns an empty stream for empty results.
    pub async fn execute_stream(self) -> Result<RecordBatchStream, SnowflakeApiError> {
        let raw = self.execute_stream_raw().await?;
        Ok(build_record_batch_stream(raw))
    }

    /// Run the query and return a stream of raw Arrow IPC blobs, one per
    /// Snowflake chunk, in original order. The inline first-page blob is
    /// yielded as item 0; external chunk downloads follow with bounded
    /// prefetch. Useful for forwarding Arrow IPC over HTTP/SSE without a
    /// decode/re-encode round-trip.
    pub async fn execute_stream_raw(self) -> Result<ArrowChunkStream, SnowflakeApiError> {
        let owned;
        let _drop_guard;
        let cancel = match self.cancel {
            Cancellation::Borrowed(c) => c,
            Cancellation::OnDrop(token, guard) => {
                owned = token;
                _drop_guard = guard;
                &owned
            }
            Cancellation::None => {
                owned = CancellationToken::new();
                &owned
            }
        };
        self.api
            .exec_arrow_stream(self.sql, self.request_id, &self.binds, cancel)
            .await
    }

    /// Validate the query and return the result schema *without executing*.
    /// Snowflake parses + type-checks the SQL (binds included for `?`
    /// placeholder type inference) and returns column metadata only — no
    /// warehouse compute is consumed and no rows are produced. Useful for
    /// codegen, dynamic UI, and pre-flight validation.
    ///
    /// `cancel` and `request_id` settings are honored but rarely matter
    /// here: describe is a single fast round-trip with no async polling.
    pub async fn describe(self) -> Result<Vec<FieldSchema>, SnowflakeApiError> {
        let params = RequestParams::or_new(self.request_id);
        let resp = self
            .api
            .run_sql_with_params::<ExecResponse>(
                self.sql,
                QueryType::JsonQuery,
                params,
                &self.binds,
                true,
            )
            .await?;
        match resp {
            ExecResponse::Query(qr) => Ok(qr.data.rowtype.into_iter().map(Into::into).collect()),
            ExecResponse::Error(e) => Err(SnowflakeApiError::ApiError(
                e.data.error_code,
                e.message.unwrap_or_default(),
            )),
            ExecResponse::QueryAsync(_) | ExecResponse::PutGet(_) => {
                Err(SnowflakeApiError::UnexpectedResponse)
            }
        }
    }
}
