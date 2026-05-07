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
use std::sync::{Arc, OnceLock};
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
    CancelQueryResponse, ExecResponseRowType, MonitoringResponse, QueryExecResponseData,
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

/// Based on the [`ExecResponseRowType`]. Carries the full type-info
/// surface Snowflake returns for a column — `length` / `byte_length` /
/// extension-type discriminator / VECTOR dimension / nested element
/// sub-schema — so codegen tools that consume `describe()` output don't
/// have to fall back to the raw response.
pub struct FieldSchema {
    pub name: String,
    // todo: is it a good idea to expose internal response struct to the user?
    pub type_: SnowflakeType,
    pub byte_length: Option<i64>,
    pub length: Option<i64>,
    pub scale: Option<i64>,
    pub precision: Option<i64>,
    pub nullable: bool,
    /// Extension-type discriminator. For Snowflake types that ride on a
    /// generic carrier (notably `GEOGRAPHY` / `GEOMETRY`, both of which
    /// arrive as `type_: SnowflakeType::Object`), this carries the
    /// upper-case real type name. Match on this when you need the
    /// distinction; ignore it for plain columns.
    pub ext_type_name: Option<String>,
    /// `VECTOR(<element>, N)` dimensionality. None for non-vector columns.
    pub vector_dimension: Option<i64>,
    /// Nested sub-schema for parametric types. For `VECTOR(FLOAT, 3)`
    /// this carries one entry describing the element. Empty for
    /// non-parametric columns.
    pub fields: Vec<FieldSchema>,
}

impl From<ExecResponseRowType> for FieldSchema {
    fn from(value: ExecResponseRowType) -> Self {
        FieldSchema {
            name: value.name,
            type_: value.type_,
            byte_length: value.byte_length,
            length: value.length,
            scale: value.scale,
            precision: value.precision,
            nullable: value.nullable,
            ext_type_name: value.ext_type_name,
            vector_dimension: value.vector_dimension,
            fields: value
                .fields
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

/// Per-query metadata Snowflake returns alongside the result body. Carried
/// on [`QueryResult`], [`RawQueryResult`], and the streaming entry points so
/// callers can correlate a result with its `queryId` (for history /
/// debugging / `cancel_query`), see which session context actually executed
/// it, and short-circuit on row count without scanning batches.
#[derive(Debug, Clone)]
pub struct QueryMetadata {
    pub query_id: String,
    /// Total rows in the full result. For Arrow responses this is the
    /// authoritative count without summing `RecordBatch::num_rows()`. None
    /// on PUT (no row concept).
    pub total_rows: Option<i64>,
    /// Total chunks the streaming path will yield (inline first-page +
    /// external chunks). Useful as the denominator for `pct = seen / total`
    /// progress display in dashboards. None for non-streaming responses.
    pub total_chunks: Option<usize>,
    /// Snowflake's internal statement-type code (e.g. `0x1000` SELECT,
    /// `0x3100` INSERT). Raw integer; use [`Self::statement_type`] for
    /// the gosnowflake-named enum mapping if you don't need fine-grained
    /// codes.
    pub statement_type_id: Option<i64>,
    /// Session context that executed the query. Optional because PUT and
    /// some session-less paths omit them.
    pub warehouse: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub role: Option<String>,
    /// Child statement query ids for multi-statement parents (returned by
    /// [`QueryBuilder::execute_multi`] / [`QueryBuilder::execute_multi_exact`]).
    /// Empty for normal single-statement queries.
    pub result_ids: Vec<String>,
}

impl QueryMetadata {
    /// Decode [`Self::statement_type_id`] into the gosnowflake-named enum.
    /// Returns `None` for PUT and any path that didn't carry a code.
    #[must_use]
    pub fn statement_type(&self) -> Option<StatementType> {
        self.statement_type_id.map(StatementType::from_code)
    }

    /// gosnowflake's `isDql`: a real read query, not a multi-statement
    /// parent envelope. Useful when iterating rows from a generic result
    /// handler — DML / DDL / coordinator envelopes have no rows worth
    /// looking at.
    #[must_use]
    pub fn is_dql(&self) -> bool {
        matches!(self.statement_type(), Some(StatementType::Select)) && self.result_ids.is_empty()
    }
}

/// Container for a successful query response: [`QueryMetadata`] + rows.
/// Arrow is returned by default for SELECTs unless the session is
/// configured otherwise.
pub struct QueryResult {
    pub metadata: QueryMetadata,
    pub data: QueryData,
}

/// Returned by [`SnowflakeApi::submit_async`] / [`QueryBuilder::submit_async`].
/// Both ids are useful: `request_id` is what [`SnowflakeApi::cancel_query`]
/// understands (same-process abort path), `query_id` is what
/// [`SnowflakeApi::query_status`] / [`SnowflakeApi::fetch_results`] expect
/// (cross-process / cross-worker dispatch).
#[derive(Debug, Clone)]
pub struct QueryHandle {
    pub request_id: Uuid,
    pub query_id: String,
}

/// Mirrors gosnowflake's `monitoring.go` query-status constants. `Other`
/// is the catch-all so a new server-side status doesn't immediately break
/// callers; treat unknown values as non-terminal until proven otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStatus {
    Running,
    Aborting,
    Success,
    FailedWithError,
    Aborted,
    Queued,
    FailedWithIncident,
    Disconnected,
    ResumingWarehouse,
    QueueRepairingWarehouse,
    Restarted,
    Blocked,
    /// `/monitoring/queries/<id>` returned an empty `queries` array.
    /// Snowflake does this for unknown / not-yet-visible ids.
    NoData,
    Other(String),
}

impl QueryStatus {
    /// `true` if Snowflake will not transition out of this state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Success | Self::FailedWithError | Self::Aborted | Self::FailedWithIncident
        )
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// Active states that warrant continued polling. `NoData` and `Other`
    /// fall through to neither bucket: callers decide whether to retry.
    #[must_use]
    pub fn is_running(&self) -> bool {
        matches!(
            self,
            Self::Running
                | Self::Queued
                | Self::ResumingWarehouse
                | Self::QueueRepairingWarehouse
                | Self::Blocked
                | Self::Restarted
        )
    }

    fn from_wire(s: &str) -> Self {
        match s {
            "RUNNING" => Self::Running,
            "ABORTING" => Self::Aborting,
            "SUCCESS" => Self::Success,
            "FAILED_WITH_ERROR" => Self::FailedWithError,
            "ABORTED" => Self::Aborted,
            "QUEUED" => Self::Queued,
            "FAILED_WITH_INCIDENT" => Self::FailedWithIncident,
            "DISCONNECTED" => Self::Disconnected,
            "RESUMING_WAREHOUSE" => Self::ResumingWarehouse,
            // gosnowflake spells this `QUEUED_REPARING_WAREHOUSE` (their
            // typo, on the wire); preserve the exact string match.
            "QUEUED_REPARING_WAREHOUSE" => Self::QueueRepairingWarehouse,
            "RESTARTED" => Self::Restarted,
            "BLOCKED" => Self::Blocked,
            "NO_DATA" => Self::NoData,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// Decoded `statement_type_id`, mirroring gosnowflake's named constants
/// (`connection.go` defines exactly these four; everything else is `Other`).
/// gosnowflake's grouping is intentionally coarse: INSERT / UPDATE / DELETE /
/// MERGE all map to [`StatementType::Dml`] by way of being inside the
/// `[0x3000, 0x3500]` range. If you need finer granularity, compare against
/// the raw [`QueryMetadata::statement_type_id`] integer directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementType {
    /// `0x1000` (4096). Pure read query.
    Select,
    /// `0x3000` (12288). Generic DML: INSERT / UPDATE / DELETE / MERGE.
    Dml,
    /// `0x3500` (13568). Multi-table INSERT (the `INSERT ALL` form).
    MultiTableInsert,
    /// `0xA000` (40960). Multi-statement parent envelope. Note: gosnowflake
    /// notes this code can collide with single-INSERT in some server
    /// responses; when [`QueryMetadata::result_ids`] is non-empty you've
    /// got a real multi-statement parent.
    Multistatement,
    Other(i64),
}

impl StatementType {
    pub const SELECT: i64 = 0x1000;
    pub const DML: i64 = 0x3000;
    pub const MULTI_TABLE_INSERT: i64 = 0x3500;
    pub const MULTISTATEMENT: i64 = 0xA000;

    #[must_use]
    pub fn from_code(v: i64) -> Self {
        match v {
            Self::SELECT => Self::Select,
            Self::DML => Self::Dml,
            Self::MULTI_TABLE_INSERT => Self::MultiTableInsert,
            Self::MULTISTATEMENT => Self::Multistatement,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub fn code(self) -> i64 {
        match self {
            Self::Select => Self::SELECT,
            Self::Dml => Self::DML,
            Self::MultiTableInsert => Self::MULTI_TABLE_INSERT,
            Self::Multistatement => Self::MULTISTATEMENT,
            Self::Other(v) => v,
        }
    }

    /// `true` for any code in gosnowflake's DML range (`[0x3000, 0x3500]`),
    /// covering `Dml` and `MultiTableInsert` plus any unnamed sub-codes
    /// that fell through to `Other`.
    #[must_use]
    pub fn is_dml(self) -> bool {
        match self {
            Self::Dml | Self::MultiTableInsert => true,
            Self::Other(c) => (Self::DML..=Self::MULTI_TABLE_INSERT).contains(&c),
            _ => false,
        }
    }
}

pub enum QueryData {
    Arrow(Vec<RecordBatch>),
    Json(JsonResult),
    Empty,
}

/// Raw counterpart to [`QueryResult`]: Arrow IPC bytes or JSON, plus
/// metadata. Convertible into [`QueryResult`] via
/// [`RawQueryResult::deserialize_arrow`].
pub struct RawQueryResult {
    pub metadata: QueryMetadata,
    pub data: RawQueryData,
}

pub enum RawQueryData {
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

/// Recognizes a leading `PUT` statement (case-insensitive, optionally
/// preceded by block comments). Compiled once on first use; PUT detection
/// runs on every `exec_raw` call so amortizing the compile is meaningful.
fn put_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(?:/\*.*\*/\s*)*put\s+").expect("static regex compiles"))
}

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

fn monitoring_status(resp: &MonitoringResponse) -> QueryStatus {
    resp.data
        .queries
        .first()
        .map_or(QueryStatus::NoData, |q| QueryStatus::from_wire(&q.status))
}

/// Pull `QueryMetadata` and a normalized body out of a successful query
/// response. Shared by the live exec path (`resolve_arrow_query`) and the
/// fetch-by-id path (`resolve_fetch_by_id`); they only differ in how the
/// response was obtained.
fn metadata_and_body_from(
    data: QueryExecResponseData,
) -> Result<(QueryMetadata, ResolvedArrowResult), SnowflakeApiError> {
    let inline_present = data.rowset_base64.as_ref().is_some_and(|s| !s.is_empty());
    let total_chunks = Some(data.chunks.len() + usize::from(inline_present));

    let result_ids = data
        .result_ids
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let metadata = QueryMetadata {
        query_id: data.query_id,
        total_rows: Some(data.total),
        total_chunks,
        statement_type_id: Some(data.statement_type_id),
        warehouse: data.final_warehouse_name,
        database: data.final_database_name,
        schema: data.final_schema_name,
        role: Some(data.final_role_name),
        result_ids,
    };

    let body = if data.returned == 0 {
        ResolvedArrowResult::Empty
    } else if let Some(value) = data.rowset {
        // JSON for SELECT only happens when the session is configured for it
        // (debugging path); the default for SELECT is Arrow.
        ResolvedArrowResult::Json(JsonResult {
            value,
            schema: data.rowtype.into_iter().map(Into::into).collect(),
        })
    } else if let Some(base64) = data.rowset_base64 {
        ResolvedArrowResult::Chunked {
            inline_base64: if base64.is_empty() {
                None
            } else {
                Some(base64)
            },
            chunks: data.chunks,
            chunk_headers: data.chunk_headers,
        }
    } else {
        return Err(SnowflakeApiError::BrokenResponse);
    };
    Ok((metadata, body))
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
        let data = match self.data {
            RawQueryData::Bytes(bytes) => QueryData::Arrow(Self::flat_bytes_to_batches(bytes)?),
            RawQueryData::Json(j) => QueryData::Json(j),
            RawQueryData::Empty => QueryData::Empty,
        };
        Ok(QueryResult {
            metadata: self.metadata,
            data,
        })
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

/// Default heartbeat interval when `client_session_keep_alive` is enabled
/// without an explicit value. Matches gosnowflake's typical effective period
/// (`master_validity / 4`, with `master_validity` defaulting to 4h).
const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(3600);

#[must_use]
pub struct SnowflakeApiBuilder {
    pub auth: AuthArgs,
    client: Option<ClientWithMiddleware>,
    keep_alive: Option<Duration>,
}

impl SnowflakeApiBuilder {
    pub fn new(auth: AuthArgs) -> Self {
        Self {
            auth,
            client: None,
            keep_alive: None,
        }
    }

    pub fn with_client(mut self, client: ClientWithMiddleware) -> Self {
        self.client = Some(client);
        self
    }

    /// Enable / disable the background `/session/heartbeat` task. When on,
    /// uses [`DEFAULT_KEEP_ALIVE_INTERVAL`]; for an explicit period use
    /// [`Self::with_keep_alive_interval`]. Equivalent to gosnowflake's
    /// `client_session_keep_alive` parameter.
    pub fn with_keep_alive(mut self, enabled: bool) -> Self {
        self.keep_alive = enabled.then_some(DEFAULT_KEEP_ALIVE_INTERVAL);
        self
    }

    /// Enable the heartbeat task with a caller-chosen interval. Implies
    /// `with_keep_alive(true)`.
    pub fn with_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.keep_alive = Some(interval);
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
        let session = Arc::new(session);
        let keep_alive = self
            .keep_alive
            .map(|interval| KeepAliveTask::spawn(Arc::clone(&session), interval));

        Ok(SnowflakeApi {
            connection: Arc::clone(&connection),
            session,
            account_identifier,
            keep_alive,
        })
    }
}

/// Snowflake API, keeps connection pool and manages session for you
pub struct SnowflakeApi {
    connection: Arc<Connection>,
    session: Arc<Session>,
    account_identifier: String,
    // Held for Drop side-effect: cancels the heartbeat task with the API.
    #[allow(dead_code)]
    keep_alive: Option<KeepAliveTask>,
}

/// Background `/session/heartbeat` poller. Spawned by the builder when
/// `with_keep_alive` is set; the held `DropGuard` cancels the task when the
/// `SnowflakeApi` is dropped, and the task observes that via its `select!`
/// loop and exits.
struct KeepAliveTask {
    _cancel: tokio_util::sync::DropGuard,
}

impl KeepAliveTask {
    fn spawn(session: Arc<Session>, interval: Duration) -> Self {
        let token = CancellationToken::new();
        let task_token = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = task_token.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
                match session.heartbeat().await {
                    Ok(()) => log::debug!("session heartbeat ok"),
                    Err(e) => log::warn!("session heartbeat failed: {e}"),
                }
            }
        });
        Self {
            _cancel: token.drop_guard(),
        }
    }
}

impl SnowflakeApi {
    /// Create a new `SnowflakeApi` object with an existing connection and session.
    pub fn new(connection: Arc<Connection>, session: Session, account_identifier: String) -> Self {
        Self {
            connection,
            session: Arc::new(session),
            account_identifier,
            keep_alive: None,
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
    pub async fn close_session(&self) -> Result<(), SnowflakeApiError> {
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
        // put commands go through a different flow and result is side-effect
        if put_regex().is_match(sql) {
            log::info!("Detected PUT query");
            let metadata = self.exec_put(sql).await?;
            Ok(RawQueryResult {
                metadata,
                data: RawQueryData::Empty,
            })
        } else {
            self.exec_arrow_raw(sql).await
        }
    }

    async fn exec_put(&self, sql: &str) -> Result<QueryMetadata, SnowflakeApiError> {
        let (_, resp) = self
            .run_sql::<ExecResponse>(sql, QueryType::JsonQuery)
            .await?;
        log::debug!("Got PUT response: {resp:?}");

        match resp {
            ExecResponse::Query(_) | ExecResponse::QueryAsync(_) => {
                Err(SnowflakeApiError::UnexpectedResponse)
            }
            ExecResponse::PutGet(pg) => {
                let metadata = QueryMetadata {
                    query_id: pg.data.query_id.clone(),
                    total_rows: None,
                    total_chunks: None,
                    statement_type_id: pg.data.statement_type_id,
                    warehouse: None,
                    database: None,
                    schema: None,
                    result_ids: Vec::new(),
                    role: None,
                };
                put::put(pg).await?;
                Ok(metadata)
            }
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
            parameters: HashMap::new(),
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
        self.exec_raw_inner(sql, None, &[], cancel, HashMap::new())
            .await
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
            .exec_raw_inner(sql, Some(request_id), &[], cancel, HashMap::new())
            .await?;
        Ok(raw.deserialize_arrow()?)
    }

    async fn exec_raw_inner(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Result<RawQueryResult, SnowflakeApiError> {
        if put_regex().is_match(sql) {
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
            if !parameters.is_empty() {
                // PUT doesn't accept session-parameter overrides; surface
                // rather than silently drop them.
                return Err(SnowflakeApiError::Unimplemented(
                    "session parameter overrides on PUT statements".to_owned(),
                ));
            }
            log::info!("Detected PUT query");
            let metadata = self.exec_put(sql).await?;
            Ok(RawQueryResult {
                metadata,
                data: RawQueryData::Empty,
            })
        } else {
            self.exec_arrow_raw_with_cancel(sql, request_id, binds, cancel, parameters)
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

    /// Cross-process / cross-session cancel by `query_id`. Sends
    /// Snowflake's `SYSTEM$CANCEL_QUERY('<id>')` system function as a
    /// regular SQL statement; works from any session that has access
    /// to the running query (the owning role, or any role with the
    /// `MONITOR` privilege on the query's session).
    ///
    /// Use this when the canceller doesn't share a process with the
    /// runner — e.g., a "POST /query" handler started the query and
    /// returned [`QueryHandle::query_id`], and a separate "POST
    /// /query/:id/cancel" handler in a different worker needs to abort
    /// it. If both ends share a process, [`Self::cancel_query`] (by
    /// `request_id`) is one round-trip cheaper.
    ///
    /// Idempotent: if the query has already finished, Snowflake
    /// returns "Query is no longer running" as a normal result and we
    /// surface `Ok(())`.
    pub async fn cancel_query_by_id(&self, query_id: &str) -> Result<(), SnowflakeApiError> {
        // Query ids are UUID-like; defensive escape for single quotes
        // in case Snowflake ever loosens the format.
        let escaped = query_id.replace('\'', "''");
        let sql = format!("SELECT SYSTEM$CANCEL_QUERY('{escaped}')");
        log::debug!("Cancelling query by id {query_id}");
        self.exec(&sql).await?;
        Ok(())
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
        self.exec_arrow_raw_with_cancel(sql, None, &[], &cancel, HashMap::new())
            .await
    }

    async fn exec_arrow_raw_with_cancel(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Result<RawQueryResult, SnowflakeApiError> {
        let (metadata, body) = self
            .resolve_arrow_query(sql, request_id, binds, cancel, parameters)
            .await?;
        let data = self.collect_chunks(body).await?;
        Ok(RawQueryResult { metadata, data })
    }

    /// Materialize all chunks into in-memory bytes, preserving Snowflake's
    /// intended order (inline first page, then external chunks). Shared by
    /// the live-exec and fetch-by-id paths.
    async fn collect_chunks(
        &self,
        body: ResolvedArrowResult,
    ) -> Result<RawQueryData, SnowflakeApiError> {
        Ok(match body {
            ResolvedArrowResult::Empty => RawQueryData::Empty,
            ResolvedArrowResult::Json(j) => RawQueryData::Json(j),
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

                RawQueryData::Bytes(bytes)
            }
        })
    }

    async fn resolve_arrow_query(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Result<(QueryMetadata, ResolvedArrowResult), SnowflakeApiError> {
        if cancel.is_cancelled() {
            return Err(SnowflakeApiError::QueryCancelled);
        }

        let params = RequestParams::or_new(request_id);

        let mut resp = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(SnowflakeApiError::QueryCancelled),
            r = self.run_sql_with_params::<ExecResponse>(sql, QueryType::ArrowQuery, params, binds, false, false, parameters.clone()) => r?,
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

        metadata_and_body_from(resp.data)
    }

    /// Submit a query without waiting for results. Returns immediately with
    /// a [`QueryHandle`] carrying both `request_id` (for [`Self::cancel_query`])
    /// and `query_id` (for [`Self::query_status`] / [`Self::fetch_results`]).
    /// Equivalent to gosnowflake's `WithAsyncMode(true)`.
    ///
    /// Useful for the three-handler dashboard pattern: one process submits,
    /// another polls, a third fetches the rows after the original HTTP
    /// request has long since closed.
    pub async fn submit_async(&self, sql: &str) -> Result<QueryHandle, SnowflakeApiError> {
        let cancel = CancellationToken::new();
        self.submit_async_inner(sql, None, &[], &cancel, HashMap::new())
            .await
    }

    async fn submit_async_inner(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Result<QueryHandle, SnowflakeApiError> {
        if cancel.is_cancelled() {
            return Err(SnowflakeApiError::QueryCancelled);
        }
        let params = RequestParams::or_new(request_id);
        let resp = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(SnowflakeApiError::QueryCancelled),
            r = self.run_sql_with_params::<ExecResponse>(
                sql,
                QueryType::ArrowQuery,
                params,
                binds,
                false,
                true,
                parameters,
            ) => r?,
        };
        let query_id = match resp {
            ExecResponse::QueryAsync(a) => a.data.query_id,
            // Fast queries can return a terminal Query body even with
            // asyncExec=true. Surface the handle and let the caller decide
            // whether to fetch (it's already executed; another round-trip
            // hits the cached result).
            ExecResponse::Query(q) => q.data.query_id,
            ExecResponse::Error(e) if is_sql_execution_cancelled(e.code.as_ref()) => {
                return Err(SnowflakeApiError::QueryCancelled);
            }
            ExecResponse::Error(e) => {
                return Err(SnowflakeApiError::ApiError(
                    e.data.error_code,
                    e.message.unwrap_or_default(),
                ));
            }
            ExecResponse::PutGet(_) => return Err(SnowflakeApiError::UnexpectedResponse),
        };
        Ok(QueryHandle {
            request_id: params.request_id,
            query_id,
        })
    }

    /// One status round-trip against `/monitoring/queries/<id>`. Does not
    /// consume warehouse credits or buffer results; safe to call from a
    /// poll loop. `query_id` typically comes from [`QueryHandle::query_id`]
    /// or `metadata.query_id` on a previous result.
    pub async fn query_status(&self, query_id: &str) -> Result<QueryStatus, SnowflakeApiError> {
        let resp = self.send_status_request(query_id).await?;
        if !resp.success && is_session_expired(resp.code.as_ref()) {
            log::debug!("Session expired during query_status; renewing and retrying once");
            self.session.force_renew().await?;
            let resp = self.send_status_request(query_id).await?;
            return Ok(monitoring_status(&resp));
        }
        Ok(monitoring_status(&resp))
    }

    async fn send_status_request(
        &self,
        query_id: &str,
    ) -> Result<MonitoringResponse, SnowflakeApiError> {
        let parts = self.session.get_token().await?;
        let resp = self
            .connection
            .request::<MonitoringResponse>(
                QueryType::MonitoringQuery(query_id.to_owned()),
                &self.account_identifier,
                &[],
                Some(&parts.session_token_auth_header),
                serde_json::Value::Null,
                None,
            )
            .await?;
        Ok(resp)
    }

    /// Fetch decoded results for a previously submitted query by id.
    /// Blocks until terminal using gosnowflake's fetch-by-id backoff
    /// (`[1, 1, 2, 3, 4, 8, 10]s`, saturating at 10s).
    pub async fn fetch_results(&self, query_id: &str) -> Result<QueryResult, SnowflakeApiError> {
        let raw = self.fetch_results_raw(query_id).await?;
        Ok(raw.deserialize_arrow()?)
    }

    /// Raw counterpart to [`Self::fetch_results`]: returns Arrow IPC bytes
    /// without deserialization (or JSON when the session is configured for
    /// it). Same blocking + backoff semantics.
    pub async fn fetch_results_raw(
        &self,
        query_id: &str,
    ) -> Result<RawQueryResult, SnowflakeApiError> {
        let cancel = CancellationToken::new();
        let (metadata, body) = self.resolve_fetch_by_id(query_id, &cancel).await?;
        let data = self.collect_chunks(body).await?;
        Ok(RawQueryResult { metadata, data })
    }

    /// Stream decoded `RecordBatch`es by query id. Blocks until Snowflake
    /// hands back a terminal envelope, then drives chunk downloads with
    /// bounded prefetch. Errors with [`SnowflakeApiError::JsonStreamUnsupported`]
    /// for JSON responses.
    pub async fn fetch_results_stream(
        &self,
        query_id: &str,
    ) -> Result<(QueryMetadata, RecordBatchStream), SnowflakeApiError> {
        let (metadata, raw) = self.fetch_results_stream_raw(query_id).await?;
        Ok((metadata, build_record_batch_stream(raw)))
    }

    /// Raw counterpart to [`Self::fetch_results_stream`]: yields Arrow IPC
    /// blobs in original Snowflake order, suitable for SSE-style forwarding.
    pub async fn fetch_results_stream_raw(
        &self,
        query_id: &str,
    ) -> Result<(QueryMetadata, ArrowChunkStream), SnowflakeApiError> {
        let cancel = CancellationToken::new();
        let (metadata, body) = self.resolve_fetch_by_id(query_id, &cancel).await?;
        let stream = match body {
            ResolvedArrowResult::Empty => stream::empty().boxed(),
            ResolvedArrowResult::Json(_) => return Err(SnowflakeApiError::JsonStreamUnsupported),
            ResolvedArrowResult::Chunked {
                inline_base64,
                chunks,
                chunk_headers,
            } => build_arrow_chunk_stream(
                Arc::clone(&self.connection),
                inline_base64,
                chunks,
                chunk_headers,
            ),
        };
        Ok((metadata, stream))
    }

    /// Submit a multi-statement payload and return one [`QueryResult`] per
    /// child statement, in source order. `count` mirrors gosnowflake's
    /// `WithMultiStatement`: pass `0` to let Snowflake count, or `N` to
    /// require an exact match (mismatch errors at submit). When `count == 1`
    /// (or `count == 0` and the SQL has only one statement), Snowflake
    /// returns the result inline and we wrap it as a single-element Vec.
    async fn execute_multi_inner(
        &self,
        sql: &str,
        request_id: Option<Uuid>,
        binds: &[Bind],
        cancel: &CancellationToken,
        count: u32,
        mut parameters: HashMap<String, serde_json::Value>,
    ) -> Result<Vec<QueryResult>, SnowflakeApiError> {
        // execute_multi sets MULTI_STATEMENT_COUNT explicitly; if a caller
        // pre-set it via with_session_param we'd otherwise silently honor
        // their value, which is confusing. Overwrite and move on.
        parameters.insert(
            "MULTI_STATEMENT_COUNT".to_owned(),
            serde_json::Value::Number(count.into()),
        );

        let (parent_metadata, parent_body) = self
            .resolve_arrow_query(sql, request_id, binds, cancel, parameters)
            .await?;

        // Single-statement payload: parent envelope IS the result.
        if parent_metadata.result_ids.is_empty() {
            let data = self.collect_chunks(parent_body).await?;
            let raw = RawQueryResult {
                metadata: parent_metadata,
                data,
            };
            return Ok(vec![raw.deserialize_arrow()?]);
        }

        // Multi-statement: fan out via the existing fetch-by-id machinery.
        // Run children in parallel; try_join_all preserves input order.
        let fetches = parent_metadata
            .result_ids
            .iter()
            .map(|child_id| async move {
                let (metadata, body) = self.resolve_fetch_by_id(child_id, cancel).await?;
                let data = self.collect_chunks(body).await?;
                let raw = RawQueryResult { metadata, data };
                Ok::<QueryResult, SnowflakeApiError>(raw.deserialize_arrow()?)
            });
        try_join_all(fetches).await
    }

    /// Drive `GET /queries/<id>/result` until terminal. Mirrors
    /// gosnowflake's `getQueryResultWithRetriesForAsyncMode`: no leading
    /// sleep on the first call, then `[1, 1, 2, 3, 4, 8, 10]s` (saturating
    /// at 10s). On `390112` we force-renew once and continue.
    async fn resolve_fetch_by_id(
        &self,
        query_id: &str,
        cancel: &CancellationToken,
    ) -> Result<(QueryMetadata, ResolvedArrowResult), SnowflakeApiError> {
        const FETCH_BY_ID_BACKOFF_S: &[u64] = &[1, 1, 2, 3, 4, 8, 10];
        let result_path = format!("queries/{query_id}/result");
        let mut step: usize = 0;
        let mut renewed = false;
        let mut first_iter = true;

        loop {
            if cancel.is_cancelled() {
                return Err(SnowflakeApiError::QueryCancelled);
            }
            if first_iter {
                first_iter = false;
            } else {
                let delay = Duration::from_secs(
                    FETCH_BY_ID_BACKOFF_S[step.min(FETCH_BY_ID_BACKOFF_S.len() - 1)],
                );
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Err(SnowflakeApiError::QueryCancelled),
                    () = tokio::time::sleep(delay) => {}
                }
                step = step.saturating_add(1);
            }

            let parts = self.session.get_token().await?;
            let resp = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(SnowflakeApiError::QueryCancelled),
                r = self.connection.request::<ExecResponse>(
                    QueryType::ArrowQueryResult(result_path.clone()),
                    &self.account_identifier,
                    &[],
                    Some(&parts.session_token_auth_header),
                    serde_json::Value::Null,
                    None,
                ) => r?,
            };

            match resp {
                ExecResponse::QueryAsync(_) => {}
                ExecResponse::Query(qr) if is_query_in_progress(qr.code.as_ref()) => {}
                ExecResponse::Error(e) if is_session_expired(e.code.as_ref()) && !renewed => {
                    log::info!("Session expired during fetch-by-id; renewing");
                    self.session.force_renew().await?;
                    renewed = true;
                }
                ExecResponse::Error(e) if is_sql_execution_cancelled(e.code.as_ref()) => {
                    return Err(SnowflakeApiError::QueryCancelled);
                }
                ExecResponse::Error(e) => {
                    return Err(SnowflakeApiError::ApiError(
                        e.data.error_code,
                        e.message.unwrap_or_default(),
                    ));
                }
                ExecResponse::Query(qr) => {
                    return metadata_and_body_from(qr.data);
                }
                ExecResponse::PutGet(_) => return Err(SnowflakeApiError::UnexpectedResponse),
            }
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
        parameters: HashMap<String, serde_json::Value>,
    ) -> Result<(QueryMetadata, ArrowChunkStream), SnowflakeApiError> {
        let (metadata, body) = self
            .resolve_arrow_query(sql, request_id, binds, cancel, parameters)
            .await?;
        let stream = match body {
            ResolvedArrowResult::Empty => stream::empty().boxed(),
            ResolvedArrowResult::Json(_) => return Err(SnowflakeApiError::JsonStreamUnsupported),
            ResolvedArrowResult::Chunked {
                inline_base64,
                chunks,
                chunk_headers,
            } => build_arrow_chunk_stream(
                Arc::clone(&self.connection),
                inline_base64,
                chunks,
                chunk_headers,
            ),
        };
        Ok((metadata, stream))
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
            .run_sql_with_params::<R>(
                sql_text,
                query_type,
                params,
                &[],
                false,
                false,
                HashMap::new(),
            )
            .await?;
        Ok((params, resp))
    }

    /// Run a SQL statement using caller-supplied request params. Used by the
    /// cancellable exec path so the caller controls the `request_id` used
    /// for both the original query and any later abort POST. `async_exec`
    /// flips the gosnowflake `WithAsyncMode` toggle: when true, Snowflake
    /// returns the `query_id` immediately (333334) instead of polling the
    /// query to completion in this same request.
    #[allow(clippy::too_many_arguments)]
    async fn run_sql_with_params<R: serde::de::DeserializeOwned>(
        &self,
        sql_text: &str,
        query_type: QueryType,
        params: RequestParams,
        binds: &[Bind],
        describe_only: bool,
        async_exec: bool,
        parameters: HashMap<String, serde_json::Value>,
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
            async_exec,
            sequence_id: parts.sequence_id,
            is_internal: false,
            describe_only,
            bindings,
            parameters,
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
    parameters: HashMap<String, serde_json::Value>,
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

    /// Override a session parameter for this request only. Equivalent to
    /// `ALTER SESSION SET <key> = <value>` but request-scoped: does not
    /// leak to subsequent queries on the same connection. Common keys:
    /// `TIMEZONE`, `QUERY_TAG`, `WEEK_START`, `USE_CACHED_RESULT`,
    /// `DATE_OUTPUT_FORMAT`, `BINARY_OUTPUT_FORMAT`, etc. Snowflake
    /// matches keys case-insensitively; uppercase is canonical.
    ///
    /// Same wire mechanism as gosnowflake's `WithStatementContext` / the
    /// SQL API's `parameters` field.
    #[must_use]
    pub fn with_session_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    /// Bulk variant of [`Self::with_session_param`].
    #[must_use]
    pub fn with_session_params<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.parameters
            .extend(params.into_iter().map(|(k, v)| (k.into(), v.into())));
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
            .exec_raw_inner(
                self.sql,
                self.request_id,
                &self.binds,
                cancel,
                self.parameters,
            )
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
    pub async fn execute_stream(
        self,
    ) -> Result<(QueryMetadata, RecordBatchStream), SnowflakeApiError> {
        let (metadata, raw) = self.execute_stream_raw().await?;
        Ok((metadata, build_record_batch_stream(raw)))
    }

    /// Run the query and return a stream of raw Arrow IPC blobs, one per
    /// Snowflake chunk, in original order. The inline first-page blob is
    /// yielded as item 0; external chunk downloads follow with bounded
    /// prefetch. Useful for forwarding Arrow IPC over HTTP/SSE without a
    /// decode/re-encode round-trip.
    pub async fn execute_stream_raw(
        self,
    ) -> Result<(QueryMetadata, ArrowChunkStream), SnowflakeApiError> {
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
            .exec_arrow_stream(
                self.sql,
                self.request_id,
                &self.binds,
                cancel,
                self.parameters,
            )
            .await
    }

    /// Run a multi-statement payload and return one [`QueryResult`] per
    /// child statement, in source order. Lets Snowflake count statements
    /// (sets `MULTI_STATEMENT_COUNT = 0`); use [`Self::execute_multi_exact`]
    /// to require an exact count.
    ///
    /// Bindings span the whole payload positionally: the first `?` in
    /// statement 1 is bind 1, the first `?` in statement 2 keeps counting.
    pub async fn execute_multi(self) -> Result<Vec<QueryResult>, SnowflakeApiError> {
        self.execute_multi_with_count(0).await
    }

    /// Like [`Self::execute_multi`], but reject the submit if the SQL
    /// doesn't contain exactly `count` statements. Mirrors gosnowflake's
    /// `WithMultiStatement(N)` strict mode. Pass `1` to assert single-statement.
    pub async fn execute_multi_exact(
        self,
        count: u32,
    ) -> Result<Vec<QueryResult>, SnowflakeApiError> {
        self.execute_multi_with_count(count).await
    }

    async fn execute_multi_with_count(
        self,
        count: u32,
    ) -> Result<Vec<QueryResult>, SnowflakeApiError> {
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
            .execute_multi_inner(
                self.sql,
                self.request_id,
                &self.binds,
                cancel,
                count,
                self.parameters,
            )
            .await
    }

    /// Submit the built query without waiting for results. See
    /// [`SnowflakeApi::submit_async`] for the deferred-fetch flow this
    /// enables. Honors `with_cancel` / `cancel_on_drop` for the submit
    /// POST itself only; the query continues running on Snowflake after
    /// the future resolves. To abort post-submit, call
    /// `cancel_query(handle.request_id)` from the same process or
    /// `SYSTEM$CANCEL_QUERY('<id>')` from any session.
    pub async fn submit_async(self) -> Result<QueryHandle, SnowflakeApiError> {
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
            .submit_async_inner(
                self.sql,
                self.request_id,
                &self.binds,
                cancel,
                self.parameters,
            )
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
                false,
                HashMap::new(),
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

#[cfg(test)]
mod tests {
    use super::{FieldSchema, SnowflakeType, StatementType};
    use crate::responses::ExecResponseRowType;
    use serde_json::json;

    #[test]
    fn rowtype_geography_rides_on_object_with_ext_type_name() {
        let json = json!({
            "name": "GEO",
            "byteLength": null,
            "length": null,
            "type": "object",
            "scale": null,
            "precision": null,
            "nullable": true,
            "extTypeName": "GEOGRAPHY",
        });
        let rt: ExecResponseRowType = serde_json::from_value(json).unwrap();
        let f: FieldSchema = rt.into();
        assert_eq!(f.type_, SnowflakeType::Object);
        assert_eq!(f.ext_type_name.as_deref(), Some("GEOGRAPHY"));
    }

    #[test]
    fn rowtype_vector_carries_dimension_and_nested_element() {
        let json = json!({
            "name": "V",
            "byteLength": null,
            "length": null,
            "type": "vector",
            "scale": null,
            "precision": null,
            "nullable": true,
            "vectorDimension": 3,
            "fields": [{
                "byteLength": null,
                "length": null,
                "type": "real",
                "scale": null,
                "precision": null,
                "nullable": false,
                "name": "",
            }],
        });
        let rt: ExecResponseRowType = serde_json::from_value(json).unwrap();
        let f: FieldSchema = rt.into();
        assert_eq!(f.type_, SnowflakeType::Vector);
        assert_eq!(f.vector_dimension, Some(3));
        assert_eq!(f.fields.len(), 1);
        assert_eq!(f.fields[0].type_, SnowflakeType::Real);
    }

    #[test]
    fn snowflake_type_decodes_defensive_variants() {
        // Map and Decfloat don't surface in current result-set metadata
        // (Snowflake collapses MAP -> object and DECFLOAT -> text in the
        // wire); these tests guard the deserialize path for the day the
        // protocol surfaces them as distinct tags.
        let map: ExecResponseRowType =
            serde_json::from_value(json!({"name": "m", "type": "map", "nullable": true})).unwrap();
        assert_eq!(FieldSchema::from(map).type_, SnowflakeType::Map);

        let decfloat: ExecResponseRowType =
            serde_json::from_value(json!({"name": "d", "type": "decfloat", "nullable": false}))
                .unwrap();
        assert_eq!(FieldSchema::from(decfloat).type_, SnowflakeType::Decfloat);
    }

    #[test]
    fn rowtype_plain_select_has_no_extension_metadata() {
        let json = json!({
            "name": "n",
            "byteLength": 8,
            "length": null,
            "type": "fixed",
            "scale": 0,
            "precision": 38,
            "nullable": false,
        });
        let rt: ExecResponseRowType = serde_json::from_value(json).unwrap();
        let f: FieldSchema = rt.into();
        assert_eq!(f.type_, SnowflakeType::Fixed);
        assert!(f.ext_type_name.is_none());
        assert!(f.vector_dimension.is_none());
        assert!(f.fields.is_empty());
        assert_eq!(f.byte_length, Some(8));
        assert_eq!(f.precision, Some(38));
    }

    #[test]
    fn statement_type_decodes_named_codes() {
        assert_eq!(StatementType::from_code(0x1000), StatementType::Select);
        assert_eq!(StatementType::from_code(0x3000), StatementType::Dml);
        assert_eq!(
            StatementType::from_code(0x3500),
            StatementType::MultiTableInsert
        );
        assert_eq!(
            StatementType::from_code(0xA000),
            StatementType::Multistatement
        );
        // Sub-codes inside the DML range fall through to Other but still
        // pass is_dml().
        assert_eq!(
            StatementType::from_code(0x3100),
            StatementType::Other(0x3100)
        );
    }

    #[test]
    fn statement_type_is_dml_covers_range() {
        assert!(StatementType::Dml.is_dml());
        assert!(StatementType::MultiTableInsert.is_dml());
        // 0x3100 = INSERT (single), unnamed in gosnowflake but inside the range.
        assert!(StatementType::from_code(0x3100).is_dml());
        // Boundary: 0x3500 is the inclusive upper end.
        assert!(StatementType::from_code(0x3500).is_dml());
        // 0x3501 is past the range — not DML.
        assert!(!StatementType::from_code(0x3501).is_dml());
        // SELECT and Multistatement are not DML.
        assert!(!StatementType::Select.is_dml());
        assert!(!StatementType::Multistatement.is_dml());
    }

    #[test]
    fn statement_type_code_round_trips() {
        for c in [0x1000_i64, 0x3000, 0x3500, 0xA000, 0x6000] {
            assert_eq!(StatementType::from_code(c).code(), c);
        }
    }
}
