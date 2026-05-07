//! End-to-end demo of querying GEOGRAPHY / GEOMETRY / VECTOR columns.
//!
//! These three Snowflake types arrive on the wire with metadata that
//! plain `type_` doesn't fully describe:
//!   - GEOGRAPHY / GEOMETRY ride on `type_: SnowflakeType::Object` with
//!     the real type in `ext_type_name` ("GEOGRAPHY" / "GEOMETRY").
//!   - VECTOR is its own `SnowflakeType::Vector` and carries dimension
//!     in `vector_dimension`, element type in `fields[0]`.
//!
//! This example queries each type and prints the schema metadata plus
//! the Arrow column type so callers can see exactly what they get.
//!
//! Reads credentials from a local `.env`. See `streaming.rs`.

extern crate firn;

use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use firn::{QueryData, SnowflakeApi, SnowflakeType};

const SQL: &str = "\
SELECT TO_GEOGRAPHY('POINT(-122.0 37.5)') AS geo,
       TO_GEOMETRY('POINT(0 0)') AS geom,
       [1.0, 2.0, 3.0]::VECTOR(FLOAT, 3) AS v,
       {'a': 1, 'b': 2, 'c': 3}::MAP(VARCHAR, INTEGER) AS m,
       [10, 20, 30]::ARRAY(INTEGER) AS a";

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    pretty_env_logger::init();

    let api = SnowflakeApi::from_env()?;

    // describe() returns the schema without executing — quick way to
    // demonstrate the metadata round-trip.
    let schema = api.query(SQL).describe().await?;
    println!("--- describe() ---");
    for f in &schema {
        println!(
            "  {:8} type_={:?} ext_type_name={:?} vector_dimension={:?} fields={}",
            f.name,
            f.type_,
            f.ext_type_name,
            f.vector_dimension,
            f.fields.len()
        );
        if let Some(t) = &f.ext_type_name {
            println!("           -> Snowflake type {t}");
        }
        if matches!(f.type_, SnowflakeType::Vector) {
            if let Some(elem) = f.fields.first() {
                println!(
                    "           -> VECTOR<{:?}, {}>",
                    elem.type_,
                    f.vector_dimension.unwrap_or(0)
                );
            }
        }
    }

    // Now actually execute and inspect the Arrow result.
    println!("\n--- execute() raw ---");
    let r = api.query(SQL).execute().await?;
    println!("query_id = {}", r.metadata.query_id);
    if let QueryData::Arrow(ref batches) = r.data {
        if let Some(b) = batches.first() {
            println!("Arrow schema (default — Snowflake demotes structured types to Utf8 JSON):");
            for f in b.schema().fields() {
                println!("  {} : {:?}", f.name(), f.data_type());
            }
        }
    }

    // Snowflake's default wire format demotes MAP / OBJECT / ARRAY to
    // Utf8 with JSON inside. cast_structured() rebuilds those columns
    // as proper Arrow Map<Utf8, V> / List<E> with element type inferred
    // from the data.
    println!("\n--- execute() + cast_structured() ---");
    let r = r.cast_structured()?;
    match r.data {
        QueryData::Arrow(batches) => {
            if let Some(b) = batches.first() {
                println!("Arrow schema (after cast):");
                for f in b.schema().fields() {
                    println!("  {} : {:?}", f.name(), f.data_type());
                }
                println!("\nfirst batch:");
                println!("{}", pretty_format_batches(std::slice::from_ref(b))?);
            }
        }
        QueryData::Json(j) => println!("json: {j}"),
        QueryData::Empty => println!("(empty)"),
    }

    Ok(())
}
