// src/logger.rs
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// Initializes a human-readable logger for the application.
pub fn init() {
    // This subscriber will format log events in a compact, human-readable
    // format, perfect for a command-line application.
    let subscriber = FmtSubscriber::builder()
        // Set the maximum level of events to log.
        // `INFO` is a good default, showing important events without being too noisy.
        .with_max_level(Level::INFO)
        // Build the subscriber.
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set up the global logger");
}
