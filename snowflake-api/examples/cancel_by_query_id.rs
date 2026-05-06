//! Cross-process cancel by `query_id`.
//!
//! Pattern: process A calls `submit_async`, persists the `query_id`
//! somewhere shared (Redis, a DB, a message), and exits. Process B
//! reads the `query_id` and calls `cancel_query_by_id`. Snowflake
//! routes the cancel to the running query via `SYSTEM$CANCEL_QUERY`
//! and the original runner observes its work being aborted.
//!
//! Reads credentials from a local `.env`. See `streaming.rs`.

extern crate snowflake_api;

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use snowflake_api::{QueryStatus, SnowflakeApi};

const SLOW_SQL: &str = "CALL SYSTEM$WAIT(60, 'SECONDS')";

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    pretty_env_logger::init();

    let api = Arc::new(SnowflakeApi::from_env()?);

    let handle = api.submit_async(SLOW_SQL).await?;
    println!("submitted: {handle:?}");

    // Wait long enough for Snowflake to schedule the query into
    // RUNNING. Without this delay the cancel can race the start.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let status = api.query_status(&handle.query_id).await?;
    println!("status before cancel: {status:?}");

    // Now cancel by query_id only. In a real cross-process flow this
    // call would happen in a different binary; here we just use the
    // same `api` to keep the example self-contained.
    api.cancel_query_by_id(&handle.query_id).await?;
    println!("cancel_query_by_id sent");

    // Verify the query reached a terminal cancelled state.
    for i in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let s = api.query_status(&handle.query_id).await?;
        println!("status[{i}]: {s:?}");
        if matches!(s, QueryStatus::Aborted | QueryStatus::FailedWithError) {
            println!("OK: query reached terminal cancelled state");
            return Ok(());
        }
        if matches!(s, QueryStatus::Success) {
            anyhow::bail!("unexpected: query succeeded before cancel landed");
        }
    }

    anyhow::bail!("query never reached terminal state within 10s")
}
