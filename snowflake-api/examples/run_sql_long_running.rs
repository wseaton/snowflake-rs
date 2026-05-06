//! Demonstrates the async-query polling path.
//!
//! Snowflake returns a poll handle (response code 333334) for any query
//! that runs longer than ~45s on the internal `/queries/v1/query-request`
//! endpoint. The recursive CTE below reliably trips that threshold on a
//! small warehouse and exercises the full polling loop end-to-end.
//!
//! Reads credentials from environment variables; see
//! `SnowflakeApi::from_env`. Set at minimum:
//!   SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, and one of:
//!     SNOWFLAKE_PASSWORD,
//!     SNOWFLAKE_PRIVATE_KEY,
//!     SNOWFLAKE_AUTHENTICATOR=externalbrowser  (with feature `browser-auth`)
//!
//! Run with: `RUST_LOG=trace cargo run --example run_sql_long_running --all-features`

extern crate snowflake_api;

use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;

use snowflake_api::{QueryData, SnowflakeApi};

const RECURSIVE_CTE: &str = "\
WITH RECURSIVE Compute_CTE AS (
    SELECT 1 AS n UNION ALL
    SELECT n + 1 FROM Compute_CTE WHERE n < 10000000
)
SELECT SUM(n) FROM Compute_CTE";

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let api = SnowflakeApi::from_env()?;
    let sql = std::env::var("SQL").ok();
    let sql = sql.as_deref().unwrap_or(RECURSIVE_CTE);

    log::info!("Running long query (this should hit the async path)");
    let started = std::time::Instant::now();
    let res = api.exec(sql).await?;
    log::info!("Query finished in {:?}", started.elapsed());
    log::info!("query_id: {}", res.metadata.query_id);

    match res.data {
        QueryData::Arrow(a) => println!("{}", pretty_format_batches(&a).unwrap()),
        QueryData::Json(j) => println!("{j}"),
        QueryData::Empty => println!("Query finished successfully"),
    }
    Ok(())
}
