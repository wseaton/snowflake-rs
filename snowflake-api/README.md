# firn

Rust client for Snowflake's internal HTTP API (the same endpoint the
official drivers use). Forked from
[`snowflake-api`](https://crates.io/crates/snowflake-api) at v0.14.0
([andrusha/snowflake-rs](https://github.com/andrusha/snowflake-rs)).

```toml
[dependencies]
firn = "0.15"
```

Default features: `cert-auth`. Optional: `browser-auth`, `polars`.

## Quick start

```rust
use firn::{QueryData, SnowflakeApi};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api = SnowflakeApi::from_env()?;
    let r = api.exec("SELECT current_version()").await?;
    match r.data {
        QueryData::Arrow(batches) => { /* ... */ }
        QueryData::Json(v) => { /* ... */ }
        QueryData::Empty => {}
    }
    Ok(())
}
```

## Features

### Auth
- password ([`with_password_auth`])
- key-pair JWT ([`with_certificate_auth`], `cert-auth` feature, default)
- external-browser SSO ([`with_browser_auth`], `browser-auth` feature)
- env-driven ([`from_env`])

### Queries
- single statement ([`run_sql.rs`](./examples/run_sql.rs))
- positional `?` bind parameters ([`run_sql_bound.rs`](./examples/run_sql_bound.rs))
- multi-statement (`execute_multi`, `execute_multi_exact`) ([`multi_statement.rs`](./examples/multi_statement.rs))
- per-request session-parameter overrides (`with_session_param`) ([`session_params.rs`](./examples/session_params.rs))
- async long-running queries with transparent polling ([`run_sql_long_running.rs`](./examples/run_sql_long_running.rs))
- submit + fetch-by-`query_id` across processes (`submit_async`, `query_status`, `fetch_results`) ([`query_by_id.rs`](./examples/query_by_id.rs))
- describe-only introspection (`describe()`) ([`describe_query.rs`](./examples/describe_query.rs))

### Results
- Arrow `RecordBatch`, with streaming and raw-IPC variants ([`streaming.rs`](./examples/streaming.rs))
- JSON results when the session is configured for JSON
- per-query `QueryMetadata`: `query_id`, `total_rows`, `total_chunks`, `statement_type_id`, executing warehouse/database/schema/role
- `cast_structured()` rewrites `MAP` / `OBJECT` / `ARRAY` columns from JSON-in-Utf8 into native Arrow `Map<Utf8, V>` / `List<E>` ([`compound_types.rs`](./examples/compound_types.rs))
- `GEOGRAPHY` / `GEOMETRY` carried via `FieldSchema::ext_type_name`; `VECTOR` via `vector_dimension` + element type
- `StatementType` enum, `is_dql()` predicate

### Cancellation
- token-based via `CancellationToken` ([`cancel_query.rs`](./examples/cancel_query.rs))
- cross-task by `request_id` (`cancel_query`) ([`cancel_by_id.rs`](./examples/cancel_by_id.rs))
- cross-process by `query_id` (`cancel_query_by_id`) ([`cancel_by_query_id.rs`](./examples/cancel_by_query_id.rs))

### Session
- session-keep-alive heartbeat (`with_keep_alive`) ([`keep_alive.rs`](./examples/keep_alive.rs))
- session-token renewal on `390112` mid-flight
- parallel queries on a shared `SnowflakeApi` with a lock-free hot path (`arc-swap`) ([`parallel_queries.rs`](./examples/parallel_queries.rs))

### Connection
- retry middleware that rotates `request_guid` per attempt and writes `retryCount` / `retryReason` / `clientStartTime` on retried `query-request` calls
- configurable connect and request timeouts
- credentials and auth tokens wrapped in [`SecretString`](https://docs.rs/secrecy/) (`Debug`-redacted, zeroized on drop)
- custom reqwest middleware injection ([`tracing/`](./examples/tracing/))

### PUT
- AWS S3 storage backend
- glob expansion (`PUT 'file:///tmp/*.csv' @stage`)
- parallel upload of small files

### Integrations
- polars `DataFrame` conversion (`polars` feature) ([`polars/`](./examples/polars/))

## Why

Snowflake exposes two HTTP APIs: the public [SQL REST API](https://docs.snowflake.com/developer-guide/sql-api/intro)
and the undocumented endpoint that the official drivers use. This crate
targets the latter, since it supports Arrow output and `PUT`/`GET`.

The wire format and retry/cancel semantics follow
[gosnowflake](https://github.com/snowflakedb/gosnowflake), the Go
driver, since it outputs Arrow by default and is the most legible
reference implementation.

## License

Apache-2.0. Original work © Andrew Korzhuev (andrusha/snowflake-rs);
fork modifications © Will Eaton. See [`LICENSE`](../LICENSE).

[`with_password_auth`]: https://docs.rs/firn/latest/firn/struct.SnowflakeApi.html#method.with_password_auth
[`with_certificate_auth`]: https://docs.rs/firn/latest/firn/struct.SnowflakeApi.html#method.with_certificate_auth
[`with_browser_auth`]: https://docs.rs/firn/latest/firn/struct.SnowflakeApi.html#method.with_browser_auth
[`from_env`]: https://docs.rs/firn/latest/firn/struct.SnowflakeApi.html#method.from_env
