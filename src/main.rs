// src/main.rs
mod compress;
mod crypto;
mod logger; // Use the new logger module
mod vault;

use clap::{Parser, Subcommand, ValueEnum};
use std::io;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "vault")]
#[command(author = "arjun7579")]
#[command(version = "1.0")]
#[command(about = "A secure, production-grade file vault.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum CompressionArg {
    /// Best for speed: very fast compression and decompression (Default).
    Zstd,
    /// Best for size: offers a higher compression ratio, compatible with zip/gzip.
    Deflate,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault in the specified directory
    New {
        #[arg(value_name = "VAULT_DIRECTORY")]
        dir: PathBuf,
        #[arg(value_name = "VAULT_NAME")]
        name: String,
    },
    /// Add a file to an existing vault
    Add {
        #[arg(short, long, value_name = "FILE_PATH")]
        file: PathBuf,
        #[arg(short, long, value_name = "VAULT_PATH")]
        vault: PathBuf,
        #[arg(
            long,
            value_enum,
            default_value_t = CompressionArg::Zstd,
            help = "Sets the compression algorithm to use.",
            long_help = "Sets the compression algorithm to use. 'zstd' is recommended for its high speed. 'deflate' is compatible with the zip/gzip format and may offer a slightly better compression ratio for some files."
        )]
        compression: CompressionArg,
    },
    /// Extract a file from the vault
    Extract {
        #[arg(short, long, value_name = "FILE_NAME")]
        file: String,
        #[arg(short, long, value_name = "VAULT_PATH")]
        vault: PathBuf,
    },
    /// Remove a file from the vault
    Rem {
        #[arg(short, long, value_name = "FILE_NAME")]
        file: String,
        #[arg(short, long, value_name = "VAULT_PATH")]
        vault: PathBuf,
    },
    /// Extract a file and then remove it from the vault
    Remex {
        #[arg(short, long, value_name = "FILE_NAME")]
        file: String,
        #[arg(short, long, value_name = "VAULT_PATH")]
        vault: PathBuf,
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output: PathBuf,
    },
    /// Check the integrity of the vault and its entries
    Check {
        /// Path to the vault file (.vlt)
        #[arg(short, long, value_name = "VAULT_PATH")]
        vault: PathBuf,
    },
    /// List all files stored in the vault
    List {
        /// Path to the vault file (.vlt)
        #[arg(short, long, value_name = "VAULT_PATH")]
        vault: PathBuf,
    },
    /// Permanently delete an entire vault
    Delete {
        /// Path to the vault file (.vlt) to be deleted
        #[arg(value_name = "VAULT_PATH")]
        vault: PathBuf,
    },
}

fn main() -> io::Result<()> {
    // Initialize the logger at the very start of the application.
    logger::init();

    let cli = Cli::parse();

    // Use a top-level instrument span to capture the entire command's execution.
    let span = tracing::info_span!("command_execution", command = ?std::env::args().collect::<Vec<_>>());
    let _enter = span.enter();

    match cli.command {
        Commands::New { dir, name } => vault::create_vault(&dir, &name),
        Commands::Add {
            file,
            vault,
            compression,
        } => {
            let algo = match compression {
                CompressionArg::Deflate => compress::Algorithm::Deflate,
                CompressionArg::Zstd => compress::Algorithm::Zstd,
            };
            vault::add_file(&file, &vault, algo)
        }
        Commands::Extract { file, vault } => vault::extract_file(&file, &vault),
        Commands::Rem { file, vault } => vault::remove_file(&file, &vault),
        Commands::Remex {
            file,
            vault,
            output,
        } => vault::remex_file(&file, &vault, &output),
        Commands::Check { vault } => vault::check_vault(&vault),
        Commands::List { vault } => vault::list_files(&vault),
        Commands::Delete { vault } => vault::delete_vault(&vault),
    }
}
