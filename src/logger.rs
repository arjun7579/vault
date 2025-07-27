// src/logger.rs
use tracing_subscriber::fmt::format::FmtSpan;

/// Initializes the structured JSON logger for the application.
pub fn init() {
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .json()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set up the global logger");
}