# firn

Rust client for Snowflake's internal HTTP API. Forked from
[andrusha/snowflake-rs](https://github.com/andrusha/snowflake-rs) /
[`snowflake-api`](https://crates.io/crates/snowflake-api) at v0.14.0.

- [`firn`](./snowflake-api) — published crate; client for the
  undocumented public API. See [`snowflake-api/README.md`](./snowflake-api/README.md)
  for features and usage.
- [`snowflake-jwt`](./jwt) — JWT helper for the documented
  [SQL REST API](https://docs.snowflake.com/developer-guide/sql-api/intro).
  Inherited from upstream; not republished by this fork.
