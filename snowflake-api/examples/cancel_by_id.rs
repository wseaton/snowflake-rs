//! Demonstrates cross-task cancellation by `request_id`.
//!
//! This is the pattern for a REST API that exposes a "cancel this query"
//! endpoint separate from the "run this query" endpoint: the runner
//! generates a `Uuid`, exposes it to the caller (e.g. as part of a "query
//! started" response), and a separate handler can later look it up and
//! call `cancel_query`.
//!
//! Reads credentials from environment variables; see `SnowflakeApi::from_env`.

extern crate snowflake_api;

use anyhow::Result;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

use snowflake_api::{SnowflakeApi, SnowflakeApiError};
use tokio_util::sync::CancellationToken;

const SLOW_QUERY: &str = "CALL SYSTEM$WAIT(60, 'SECONDS')";

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let api = Arc::new(SnowflakeApi::from_env()?);
    let cancel_after_secs: u64 = std::env::var("CANCEL_AFTER_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let request_id = Uuid::new_v4();
    log::info!("Starting query with request_id={request_id}");

    let api_clone = Arc::clone(&api);
    let handle = tokio::spawn(async move {
        // A token is still required by the API; pass a fresh one we never
        // cancel so the only path to abort is via cancel_query.
        let token = CancellationToken::new();
        api_clone
            .exec_with_request_id(SLOW_QUERY, request_id, &token)
            .await
    });

    tokio::time::sleep(Duration::from_secs(cancel_after_secs)).await;

    log::info!("Sending cancel for {request_id}");
    api.cancel_query(request_id).await?;

    match handle.await? {
        Err(e) => log::info!("Runner task returned error (expected): {e}"),
        Ok(_) => anyhow::bail!("query unexpectedly succeeded"),
    }

    // Cancelling a request_id with no matching in-flight query is idempotent.
    let stale = Uuid::new_v4();
    log::info!("Calling cancel_query on a fresh (unknown) id; expect Ok");
    match api.cancel_query(stale).await {
        Ok(()) => log::info!("Idempotent cancel returned Ok as expected"),
        Err(SnowflakeApiError::ApiError(code, msg)) => {
            anyhow::bail!("expected idempotent Ok, got ApiError({code}, {msg})")
        }
        Err(e) => anyhow::bail!("expected idempotent Ok, got: {e}"),
    }

    Ok(())
}
