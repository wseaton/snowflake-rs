//! Demonstrates per-request session parameter overrides.
//!
//! `with_session_param` injects a Snowflake session-level parameter
//! (TIMEZONE, QUERY_TAG, WEEK_START, USE_CACHED_RESULT, ...) into the
//! request body's `parameters` map. The override applies for that one
//! statement only — no `ALTER SESSION SET` is sent, no compensating
//! `UNSET` is needed, and subsequent queries on the same connection
//! see the original session values.
//!
//! Wire-compat with the SQL API's `parameters` field and gosnowflake's
//! request-scoped parameter context.
//!
//! Reads credentials from a local `.env`. See `streaming.rs`.

extern crate firn;

use anyhow::Result;
use firn::{QueryData, SnowflakeApi};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    pretty_env_logger::init();

    let api = SnowflakeApi::from_env()?;

    // 1) Baseline: read the current session timezone.
    let baseline = first_string(&api, "SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION").await?;
    println!("baseline TIMEZONE = {baseline}");

    // 2) Run a query with TIMEZONE pinned to UTC for this request only.
    let r = api
        .query("SELECT CURRENT_TIMESTAMP() AS ts")
        .with_session_param("TIMEZONE", "UTC")
        .execute()
        .await?;
    println!(
        "with TIMEZONE=UTC override -> ts row count = {}",
        r.metadata.total_rows.unwrap_or(0)
    );

    // 3) Same query without override: should still see the baseline.
    let after = first_string(&api, "SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION").await?;
    println!("post-query TIMEZONE = {after}");

    if after == baseline {
        println!("\nOK: session parameter did not leak.");
    } else {
        println!(
            "\nLEAK: session parameter changed from {baseline} to {after}; \
             expected request-scoped behavior"
        );
    }

    // 4) Bulk variant — set a few at once, including QUERY_TAG so this
    // run is easy to spot in QUERY_HISTORY. CURRENT_TIMESTAMP() formats
    // according to TIMEZONE, so the override changes the result text.
    let _ = api
        .query("SELECT CURRENT_TIMESTAMP() AS ts")
        .with_session_params([
            ("TIMEZONE", "Europe/Berlin"),
            ("QUERY_TAG", "snowflake-rs:session_params example"),
        ])
        .execute()
        .await?;
    println!("ran query with TIMEZONE=Europe/Berlin + QUERY_TAG override");

    Ok(())
}

/// Pull the first column of the first row from a SHOW PARAMETERS result.
async fn first_string(api: &SnowflakeApi, sql: &str) -> Result<String> {
    let r = api.query(sql).execute().await?;
    match r.data {
        QueryData::Json(j) => {
            // SHOW PARAMETERS comes back as JSON: rows are arrays. The 2nd
            // element of the first row is the value for the "value" column.
            let v = j
                .value
                .as_array()
                .and_then(|rows| rows.first())
                .and_then(|row| row.as_array())
                .and_then(|cols| cols.get(1))
                .and_then(|c| c.as_str())
                .unwrap_or("(missing)");
            Ok(v.to_owned())
        }
        QueryData::Arrow(_) | QueryData::Empty => Ok("(non-json)".to_owned()),
    }
}
