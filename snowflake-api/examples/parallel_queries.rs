//! Fires N concurrent queries on a fresh `SnowflakeApi` and prints each
//! task's wall-clock duration. Before the ArcSwap refactor of session.rs,
//! tasks 2..N would all stall behind task 1's session-create. After,
//! they should each see their own near-equal latency.
//!
//! `RUST_LOG=info,snowflake_api=info cargo run --example parallel_queries
//! --features browser-auth -- 5`

extern crate snowflake_api;

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use snowflake_api::SnowflakeApi;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let api = Arc::new(SnowflakeApi::from_env()?);
    let started_overall = Instant::now();

    let handles = (0..n)
        .map(|i| {
            let api = Arc::clone(&api);
            tokio::spawn(async move {
                let t = Instant::now();
                let _ = api.exec(&format!("SELECT {i} AS i")).await?;
                Ok::<_, anyhow::Error>((i, t.elapsed()))
            })
        })
        .collect::<Vec<_>>();

    for h in handles {
        let (i, dur) = h.await??;
        println!("query {i} finished in {dur:?}");
    }

    println!("\nall {n} queries done in {:?}", started_overall.elapsed());
    Ok(())
}
