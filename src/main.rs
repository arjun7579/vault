// src/main.rs
mod compress;
mod crypto;
mod logger;
mod vault;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "vault", author = "arjun7579", version = "1.0")]
#[command(about = "A secure, production-grade file vault.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum CompressionArg {
    #[clap(help = "Faster compression, good for most files (Default).")]
    Zstd,
    #[clap(help = "Higher compression ratio, compatible with zip/gzip.")]
    Deflate,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault
    New { dir: PathBuf, name: String },
    /// Add a file to a vault
    Add {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short, long)]
        vault: PathBuf,
        #[arg(long, value_enum, default_value_t = CompressionArg::Zstd)]
        compression: CompressionArg,
    },
    /// Extract a file from a vault
    Extract { file: String, vault: PathBuf },
    /// Remove a file from a vault
    Rem { file: String, vault: PathBuf },
    /// Extract and then remove a file
    Remex {
        file: String,
        vault: PathBuf,
        output: PathBuf,
    },
    /// Check the integrity of a vault
    Check { vault: PathBuf },
    /// List all files in a vault
    List { vault: PathBuf },
}

fn main() -> io::Result<()> {
    logger::init();

    let cli = Cli::parse();
    let span = tracing::info_span!("command_execution", command = ?std::env::args().collect::<Vec<_>>());
    let _enter = span.enter();

    match cli.command {
        Commands::New { dir, name } => vault::create_vault(&dir, &name),
        Commands::Add { file, vault, compression } => {
            let algo = match compression {
                CompressionArg::Zstd => compress::Algorithm::Zstd,
                CompressionArg::Deflate => compress::Algorithm::Deflate,
            };
            vault::add_file(&file, &vault, algo)
        }
        Commands::Extract { file, vault } => vault::extract_file(&file, &vault),
        Commands::Rem { file, vault } => vault::remove_file(&file, &vault),
        Commands::Remex { file, vault, output } => vault::remex_file(&file, &vault, &output),
        Commands::Check { vault } => vault::check_vault(&vault),
        Commands::List { vault } => vault::list_files(&vault),
    }
}