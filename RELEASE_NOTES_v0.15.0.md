# firn v0.15.0

First release of the crate under the name `firn`. Forked from
[`snowflake-api`](https://crates.io/crates/snowflake-api) v0.14.0
([andrusha/snowflake-rs](https://github.com/andrusha/snowflake-rs)).

```toml
[dependencies]
firn = "0.15"
```

Default features: `cert-auth`. Optional: `browser-auth`, `polars`.

## Features

### Auth
- external-browser SSO (`SnowflakeApi::with_browser_auth`, `browser-auth` feature)
- credentials and auth tokens carried in `SecretString` (`Debug`-redacted, zeroized on drop)

### Queries
- positional `?` bind parameters ([`run_sql_bound.rs`](./snowflake-api/examples/run_sql_bound.rs))
- multi-statement (`execute_multi`, `execute_multi_exact`) ([`multi_statement.rs`](./snowflake-api/examples/multi_statement.rs))
- per-request session-parameter overrides (`with_session_param`) ([`session_params.rs`](./snowflake-api/examples/session_params.rs))
- async long-running queries: transparent polling for queries that exceed the synchronous response window ([`run_sql_long_running.rs`](./snowflake-api/examples/run_sql_long_running.rs))
- submit + fetch-by-`query_id` across processes (`submit_async`, `query_status`, `fetch_results`) ([`query_by_id.rs`](./snowflake-api/examples/query_by_id.rs))
- describe-only schema introspection (`describe()`) ([`describe_query.rs`](./snowflake-api/examples/describe_query.rs))

### Results
- streaming `RecordBatch` and raw-Arrow-IPC variants ([`streaming.rs`](./snowflake-api/examples/streaming.rs))
- `QueryMetadata` returned alongside data: `query_id`, `total_rows`, `total_chunks`, `statement_type_id`, executing `warehouse` / `database` / `schema` / `role`
- `cast_structured()` rewrites `MAP` / `OBJECT` / `ARRAY` columns from JSON-in-Utf8 into native Arrow `Map<Utf8, V>` / `List<E>` ([`compound_types.rs`](./snowflake-api/examples/compound_types.rs))
- `GEOGRAPHY` / `GEOMETRY` carried via `FieldSchema::ext_type_name`; `VECTOR` via `vector_dimension` + element type
- `StatementType` enum with `is_dql()` predicate

### Cancellation
- token-based via `tokio_util::sync::CancellationToken` ([`cancel_query.rs`](./snowflake-api/examples/cancel_query.rs))
- cross-task by `request_id` (`cancel_query`) ([`cancel_by_id.rs`](./snowflake-api/examples/cancel_by_id.rs))
- cross-process by `query_id` (`cancel_query_by_id`) ([`cancel_by_query_id.rs`](./snowflake-api/examples/cancel_by_query_id.rs))

### Session
- session-keep-alive heartbeat (`with_keep_alive`, `with_keep_alive_interval`) ([`keep_alive.rs`](./snowflake-api/examples/keep_alive.rs))
- session-token renewal on `390112` mid-flight
- parallel queries on a shared `SnowflakeApi` with a lock-free hot path (`arc-swap`) ([`parallel_queries.rs`](./snowflake-api/examples/parallel_queries.rs))

### Connection
- retry middleware that rotates `request_guid` per attempt and writes `retryCount` / `retryReason` / `clientStartTime` on retried `query-request` calls
- configurable connect and request timeouts
- query-id validation
- custom reqwest middleware injection ([`tracing/`](./snowflake-api/examples/tracing/))

## Public API breaking changes vs `snowflake-api` 0.14.0

- crate renamed: `snowflake-api` → `firn`. Imports change from `use snowflake_api::...` to `use firn::...`.
- `QueryResult` is now a struct `{ metadata: QueryMetadata, data: QueryData }`. The previous enum is `QueryData`. Same shape for `RawQueryResult` / `RawQueryData`.
- Streaming methods return `(QueryMetadata, Stream<…>)` instead of just the stream.
- `connection::RequestParams` carries only `request_id` (per-attempt identifiers are managed by the retry middleware).

## Compatibility

- Apache-2.0 licensed, unchanged.
- `snowflake-jwt` not republished; depend on the upstream crate directly when needed.
- MSRV: 1.75 (matches upstream).

## Credits

Original work by [Andrew Korzhuev](https://github.com/andrusha)
([andrusha/snowflake-rs](https://github.com/andrusha/snowflake-rs)).
Fork maintained by [@wseaton](https://github.com/wseaton).
