use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use reqwest_middleware::Extension;
use reqwest_tracing::{OtelName, SpanBackendWithUrl};
use tracing_subscriber::layer::SubscriberExt;

use firn::connection::Connection;
use firn::{AuthArgs, QueryData, SnowflakeApiBuilder};

#[tokio::main]
async fn main() -> Result<()> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint("http://localhost:4317")
        .build()?;
    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(Resource::new(vec![KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
            "snowflake-rust-client-demo",
        )]))
        .build();
    let tracer = provider.tracer("snowflake");

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    let subscriber = tracing_subscriber::Registry::default().with(telemetry);
    tracing::subscriber::set_global_default(subscriber)?;

    dotenv::dotenv().ok();

    let client = Connection::default_client_builder()?
        .with_init(Extension(OtelName(std::borrow::Cow::Borrowed("firn"))))
        .with(reqwest_tracing::TracingMiddleware::<SpanBackendWithUrl>::new());

    let builder = SnowflakeApiBuilder::new(AuthArgs::from_env()?).with_client(client.build());
    let api = builder.build()?;

    run_in_span(&api).await?;

    global::shutdown_tracer_provider();

    Ok(())
}

#[tracing::instrument(name = "snowflake_api", skip(api))]
async fn run_in_span(api: &firn::SnowflakeApi) -> anyhow::Result<()> {
    let res = api.exec("select 'hello from snowflake' as col1;").await?;
    println!("query_id: {}", res.metadata.query_id);

    match res.data {
        QueryData::Arrow(a) => {
            println!("{}", pretty_format_batches(&a).unwrap());
        }
        QueryData::Json(j) => {
            println!("{}", j);
        }
        QueryData::Empty => {
            println!("Query finished successfully")
        }
    }

    Ok(())
}
