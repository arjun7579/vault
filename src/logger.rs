// src/logger.rs
use tracing_subscriber::fmt::format::FmtSpan;

/// Initializes the structured JSON logger for the application.
pub fn init() {
    // This subscriber will format log events as JSON and print them to standard output.
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        // Set the maximum level of events to log (e.g., INFO, WARN, ERROR)
        .with_max_level(tracing::Level::INFO)
        // Include timing information for operations wrapped in `#[instrument]`
        .with_span_events(FmtSpan::CLOSE)
        // The output format
        .json()
        .finish();

    // Set this subscriber as the global default for the entire application.
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set up the global logger");
}