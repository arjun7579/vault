use tracing::Level;
use tracing_subscriber::FmtSubscriber;

// Initializer for logger
pub fn init() {
    let subscriber = FmtSubscriber::builder()
        
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set up the global logger");
}
