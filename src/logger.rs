use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// Initializes a human-readable logger for the application.
pub fn init() {
    let subscriber = FmtSubscriber::builder()
        // Set the maximum level of events to log (e.g., INFO, WARN, ERROR).
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set up the global logger");
}