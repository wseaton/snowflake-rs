//! Demonstrates the deferred-fetch flow: submit, poll status, fetch
//! results — three round-trips that can each happen in a different task,
//! worker, or process.
//!
//! Real-world shape (dashboard):
//!   POST /query              — handler calls `submit_async`, returns the
//!                              `query_id` to the client.
//!   GET  /query/:id/status   — separate handler calls `query_status`.
//!   GET  /query/:id/results  — yet another handler calls `fetch_results`.
//!
//! Cross-process cancel: persist `request_id` alongside `query_id` and
//! call `cancel_query(request_id)` from the same process, or run
//! `SYSTEM$CANCEL_QUERY('<id>')` as a regular SQL statement from any
//! session.
//!
//! Reads credentials from a local `.env` (via `dotenvy`) and then
//! `SnowflakeApi::from_env`. See `streaming.rs` for required env vars.

extern crate firn;

use std::time::Duration;

use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use firn::{QueryData, QueryStatus, SnowflakeApi};

// `seq4(GENERATOR(ROWCOUNT => N))` is a cheap way to make Snowflake do
// real work for a few seconds — we want to actually see RUNNING -> SUCCESS
// transitions, not just SUCCESS on the first poll.
const DEFAULT_SQL: &str = "SELECT seq4() AS n FROM TABLE(GENERATOR(ROWCOUNT => 500000))";

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    pretty_env_logger::init();

    let api = SnowflakeApi::from_env()?;
    let sql = std::env::var("SQL").ok();
    let sql = sql.as_deref().unwrap_or(DEFAULT_SQL);

    let handle = api.submit_async(sql).await?;
    log::info!("Submitted: {handle:?}");
    println!("query_id   = {}", handle.query_id);
    println!("request_id = {}", handle.request_id);

    // Quick peek loop. The fetch path below blocks until terminal anyway,
    // so this is here just to demonstrate the cross-process status check.
    for i in 0..3 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status = api.query_status(&handle.query_id).await?;
        println!("status[{i}] = {status:?}");
        if matches!(status, QueryStatus::Success) {
            break;
        }
    }

    let result = api.fetch_results(&handle.query_id).await?;
    println!("fetched query_id = {}", result.metadata.query_id);
    println!(
        "rows = {}, chunks = {}",
        result.metadata.total_rows.unwrap_or(0),
        result.metadata.total_chunks.unwrap_or(0)
    );

    match result.data {
        QueryData::Arrow(batches) => {
            if let Some(first) = batches.first() {
                println!(
                    "first batch: {} rows x {} cols",
                    first.num_rows(),
                    first.num_columns()
                );
                println!("{}", pretty_format_batches(std::slice::from_ref(first))?);
            } else {
                println!("(no batches)");
            }
        }
        QueryData::Json(j) => println!("json: {j}"),
        QueryData::Empty => println!("(empty)"),
    }

    Ok(())
}
