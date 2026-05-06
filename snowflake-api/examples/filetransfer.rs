use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use clap::Parser;
use snowflake_api::{QueryData, SnowflakeApi};

extern crate snowflake_api;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    csv_path: String,
}

// SNOWFLAKE_ACCOUNT=... SNOWFLAKE_USER=... SNOWFLAKE_PASSWORD=... SNOWFLAKE_DATABASE=... SNOWFLAKE_SCHEMA=... \
//   cargo run --example filetransfer --  --csv-path $(pwd)/examples/oscar_age_male.csv
#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let args = Args::parse();
    let api = SnowflakeApi::from_env()?;

    log::info!("Creating table");
    api.exec(
        "CREATE OR REPLACE TABLE OSCAR_AGE_MALE(Index integer, Year integer, Age integer, Name varchar, Movie varchar);"
    ).await?;

    log::info!("Uploading CSV file");
    api.exec(&format!("PUT file://{} @%OSCAR_AGE_MALE;", &args.csv_path))
        .await?;

    log::info!("Create temporary file format");
    api.exec(
        "CREATE OR REPLACE TEMPORARY FILE FORMAT CUSTOM_CSV_FORMAT TYPE = CSV COMPRESSION = NONE FIELD_DELIMITER = ',' FILE_EXTENSION = 'csv' SKIP_HEADER = 1 FIELD_OPTIONALLY_ENCLOSED_BY = '\"' TRIM_SPACE = TRUE SKIP_BLANK_LINES = TRUE;"
    ).await?;

    log::info!("Copying into table");
    api.exec("COPY INTO OSCAR_AGE_MALE FILE_FORMAT = CUSTOM_CSV_FORMAT;")
        .await?;

    log::info!("Querying for results");
    let res = api.exec("SELECT * FROM OSCAR_AGE_MALE;").await?;
    log::info!("query_id: {}", res.metadata.query_id);

    match res.data {
        QueryData::Arrow(a) => {
            println!("{}", pretty_format_batches(&a).unwrap());
        }
        QueryData::Empty => {
            println!("Nothing was returned");
        }
        QueryData::Json(j) => {
            println!("{j}");
        }
    }

    api.close_session().await?;

    Ok(())
}
