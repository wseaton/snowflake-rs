//! Demonstrates the opt-in `/session/heartbeat` background task. By default
//! Snowflake idles a session out after ~4h; for long-lived dashboard apps
//! that hold a `SnowflakeApi` across a process lifetime, enabling
//! `with_keep_alive` keeps the cached session token valid.
//!
//! Run with a short interval to see the heartbeat fire repeatedly:
//!
//! ```text
//! RUST_LOG=info,firn=debug \
//!   cargo run --example keep_alive
//! ```
//!
//! The first `exec` triggers login. Subsequent heartbeats keep the session
//! alive while `tokio::time::sleep` simulates a quiet dashboard. The task
//! is aborted when `api` is dropped at the end of `main`.

extern crate firn;

use std::time::Duration;

use anyhow::Result;
use firn::{AuthArgs, SnowflakeApiBuilder};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    pretty_env_logger::init();

    let api = SnowflakeApiBuilder::new(AuthArgs::from_env()?)
        .with_keep_alive_interval(Duration::from_secs(15))
        .build()?;

    let _ = api.exec("SELECT current_user()").await?;
    println!("logged in; idling for 60s while heartbeat fires...");
    tokio::time::sleep(Duration::from_secs(60)).await;

    let _ = api.exec("SELECT current_timestamp()").await?;
    println!("done");
    Ok(())
}
