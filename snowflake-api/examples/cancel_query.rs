//! Demonstrates token-based mid-flight query cancellation.
//!
//! Kicks off a long-running recursive CTE, waits 5 seconds (override with
//! `CANCEL_AFTER_SECS=...`), then cancels via `CancellationToken::cancel()`.
//! Expects `QueryCancelled`. Then runs a quick `SELECT 1` to confirm the
//! session survived the abort.
//!
//! Reads credentials from environment variables; see `SnowflakeApi::from_env`.

extern crate snowflake_api;

use anyhow::Result;
use std::{sync::Arc, time::Duration};

use snowflake_api::{SnowflakeApi, SnowflakeApiError};
use tokio_util::sync::CancellationToken;

// Procedural wait: not cached by Snowflake's result cache, so we get a
// reliable long-running query for testing cancellation. ~60s default;
// override via the SQL env var if needed.
const SLOW_QUERY: &str = "CALL SYSTEM$WAIT(60, 'SECONDS')";

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let api = Arc::new(SnowflakeApi::from_env()?);
    let cancel_after_secs: u64 = std::env::var("CANCEL_AFTER_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let api_clone = Arc::clone(&api);

    let handle = tokio::spawn(async move {
        api_clone
            .exec_with_cancel(SLOW_QUERY, &cancel_clone)
            .await
    });

    log::info!("Query started; cancelling in {cancel_after_secs}s");
    tokio::time::sleep(Duration::from_secs(cancel_after_secs)).await;

    log::info!("Firing cancel");
    cancel.cancel();

    match handle.await? {
        Err(SnowflakeApiError::QueryCancelled) => {
            log::info!("Query was cancelled as expected");
        }
        Ok(_) => anyhow::bail!("query unexpectedly succeeded"),
        Err(e) => anyhow::bail!("query failed with unexpected error: {e}"),
    }

    log::info!("Confirming session is still alive");
    let _ = api.exec("SELECT 1").await?;
    log::info!("Session OK");
    Ok(())
}
