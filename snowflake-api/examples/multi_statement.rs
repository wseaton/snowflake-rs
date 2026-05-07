//! Demonstrates multi-statement execution.
//!
//! Snowflake rejects multi-statement SQL by default unless
//! `MULTI_STATEMENT_COUNT` is set on the request. We always set it from
//! `execute_multi()` (count=0, server counts) or `execute_multi_exact(N)`
//! (strict mode that errors on mismatch — same shape as gosnowflake's
//! `WithMultiStatement`).
//!
//! Bindings are positional and span the entire payload: bind 1 maps to
//! the first `?` anywhere in the SQL, bind 2 the next, and so on.
//!
//! Reads credentials from a local `.env` (via `dotenvy`) and then
//! `SnowflakeApi::from_env`. See `streaming.rs` for required env vars.

extern crate firn;

use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use firn::{QueryData, SnowflakeApi};

const SQL: &str = "\
SELECT 1 AS a;
SELECT 'two' AS b, ? AS bind;
SELECT seq4() AS n FROM TABLE(GENERATOR(ROWCOUNT => 5));";

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    pretty_env_logger::init();

    let api = SnowflakeApi::from_env()?;

    let results = api
        .query(SQL)
        .bind("hello from bind 1")
        .execute_multi()
        .await?;

    println!("got {} child result(s)\n", results.len());

    for (i, r) in results.iter().enumerate() {
        println!("--- statement {i} ---");
        println!(
            "query_id = {}, rows = {}",
            r.metadata.query_id,
            r.metadata.total_rows.unwrap_or(0)
        );
        match &r.data {
            QueryData::Arrow(batches) => {
                if let Some(first) = batches.first() {
                    println!("{}", pretty_format_batches(std::slice::from_ref(first))?);
                } else {
                    println!("(no batches)");
                }
            }
            QueryData::Json(j) => println!("json: {j}"),
            QueryData::Empty => println!("(empty)"),
        }
        println!();
    }

    // Strict mode: this should match the actual count (3 statements).
    let strict = api
        .query(SQL)
        .bind("strict-mode bind")
        .execute_multi_exact(3)
        .await?;
    println!("strict mode returned {} result(s)", strict.len());

    Ok(())
}
