//! Demonstrates `describeOnly` — fetch a query's result schema without
//! executing it. No warehouse compute is consumed. Intended for codegen
//! and pre-flight validation paths.

extern crate snowflake_api;

use anyhow::Result;
use snowflake_api::SnowflakeApi;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let api = SnowflakeApi::from_env()?;

    let schema = api
        .query("SELECT ?::NUMBER AS n, ?::VARCHAR AS s, CURRENT_TIMESTAMP() AS ts")
        .bind(42_i64)
        .bind("hi")
        .describe()
        .await?;

    println!(
        "{:<20} {:<14} {:<5} {:<9} nullable",
        "name", "type", "scale", "precision"
    );
    for f in &schema {
        println!(
            "{:<20} {:<14?} {:<5?} {:<9?} {}",
            f.name, f.type_, f.scale, f.precision, f.nullable
        );
    }
    Ok(())
}
