//! Demonstrates the Arrow-IPC streaming path: chunks are downloaded with
//! bounded prefetch (default 4) and yielded in original Snowflake order.
//!
//! Reads credentials from a local `.env` (via `dotenvy`) and then
//! `SnowflakeApi::from_env`. Set at minimum:
//!   SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, and one of:
//!     SNOWFLAKE_PASSWORD,
//!     SNOWFLAKE_PRIVATE_KEY,
//!     SNOWFLAKE_AUTHENTICATOR=externalbrowser  (with feature `browser-auth`)
//!
//! Run with: `cargo run --example streaming --all-features -- --mode batches`
//! Pass `SQL=...` env var to override the default query (use one large
//! enough to produce multiple chunks, e.g. a few million rows from
//! `SNOWFLAKE_SAMPLE_DATA`).

extern crate firn;

use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use clap::Parser;
use futures::StreamExt;

use firn::SnowflakeApi;

const DEFAULT_SQL: &str = "\
SELECT L_ORDERKEY, L_LINENUMBER, L_QUANTITY, L_EXTENDEDPRICE
FROM SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.LINEITEM
LIMIT 5000000";

#[derive(clap::ValueEnum, Clone, Debug)]
enum Mode {
    /// Stream decoded RecordBatches; pretty-print the first.
    Batches,
    /// Stream raw Arrow IPC blobs (one per Snowflake chunk). Useful for
    /// SSE forwarding without a decode/re-encode round-trip.
    Raw,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, value_enum, default_value_t = Mode::Batches)]
    mode: Mode,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    pretty_env_logger::init();

    let args = Args::parse();

    let api = SnowflakeApi::from_env()?;
    let sql = std::env::var("SQL").ok();
    let sql = sql.as_deref().unwrap_or(DEFAULT_SQL);

    match args.mode {
        Mode::Batches => {
            let (meta, mut stream) = api.query(sql).execute_stream().await?;
            println!("query_id: {}", meta.query_id);
            let total_chunks = meta.total_chunks.unwrap_or(0);
            let mut idx = 0usize;
            let mut total_rows = 0usize;
            while let Some(batch) = stream.next().await {
                let batch = batch?;
                total_rows += batch.num_rows();
                println!(
                    "batch {idx}: {} rows, {} cols (cumulative {} rows)",
                    batch.num_rows(),
                    batch.num_columns(),
                    total_rows
                );
                if idx == 0 {
                    println!("{}", pretty_format_batches(std::slice::from_ref(&batch))?);
                }
                idx += 1;
            }
            println!(
                "done; {idx} batch(es), {total_rows} row(s) (of {} chunks total)",
                total_chunks
            );
        }
        Mode::Raw => {
            let (meta, mut stream) = api.query(sql).execute_stream_raw().await?;
            println!("query_id: {}", meta.query_id);
            let total_chunks = meta.total_chunks.unwrap_or(0);
            let mut idx = 0usize;
            let mut total_bytes = 0usize;
            while let Some(blob) = stream.next().await {
                let blob = blob?;
                idx += 1;
                let pct = (idx * 100).checked_div(total_chunks).unwrap_or(0);
                println!(
                    "chunk {idx}/{total_chunks} ({pct}%): {} bytes of Arrow IPC",
                    blob.len()
                );
                total_bytes += blob.len();
            }
            println!("done; {idx} chunk(s), {total_bytes} bytes total");
        }
    }

    Ok(())
}
