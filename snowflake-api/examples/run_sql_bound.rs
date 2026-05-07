//! Demonstrates positional bind parameters via the query builder.
//!
//! Snowflake's internal API binds `?` placeholders by 1-indexed position.
//! Mixing types is fine; integers, strings, and booleans here all flow
//! through the same builder.
//!
//! Reads credentials from environment variables; see `SnowflakeApi::from_env`.

extern crate firn;

use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;

use firn::{Bind, QueryData, SnowflakeApi};

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let api = SnowflakeApi::from_env()?;

    // Heterogeneous binds: int + text + bool. The Into<Bind> impls cover
    // the common primitive types so callers don't have to spell out
    // `Bind::fixed`/`Bind::text` for the simple cases.
    let res = api
        .query("SELECT ? AS num, ? AS msg, ? AS flag")
        .bind(42_i64)
        .bind("hello from rust")
        .bind(true)
        .execute()
        .await?;

    println!("query_id: {}", res.metadata.query_id);
    match res.data {
        QueryData::Arrow(a) => println!("{}", pretty_format_batches(&a).unwrap()),
        QueryData::Json(j) => println!("{j}"),
        QueryData::Empty => println!("Query finished with empty result"),
    }

    // Explicit constructors are still available when you want to nail
    // down the Snowflake type (e.g., for typed NULLs).
    let res = api
        .query("SELECT ?::VARCHAR AS s, ?::NUMBER AS n")
        .binds([Bind::text("typed"), Bind::null("FIXED")])
        .execute()
        .await?;
    if let QueryData::Arrow(a) = res.data {
        println!("{}", pretty_format_batches(&a).unwrap());
    }

    Ok(())
}
