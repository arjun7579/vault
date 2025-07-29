mod compress;
mod crypto;
mod logger;
mod vault;

use clap::{Parser, Subcommand, ValueEnum};
use std::io;
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
    //zstd is the default
    Zstd,
    Deflate,
}

#[derive(Subcommand)]
enum Commands {
    ///create a new vault
    New { dir: PathBuf, name: String },
    /// add a file to a vault
    Add {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short, long)]
        vault: PathBuf,
        #[arg(long, value_enum, default_value_t = CompressionArg::Zstd)]
        compression: CompressionArg,
    },
    /// extract a file from a vault
    Extract { file: String, vault: PathBuf },
    /// remove a file from a vault
    Rem { file: String, vault: PathBuf },
    /// extract and then remove a file
    Remex {
        file: String,
        vault: PathBuf,
        output: PathBuf,
    },
    /// check the integrity of a vault
    Check { vault: PathBuf },
    /// list all files in a vault
    List { vault: PathBuf },
    /// permanently delete an entire vault
    Delete {
        #[arg(value_name = "VAULT_PATH")]
        vault: PathBuf,
    },
    /// display the activity log for a vault
    Log {
        #[arg(value_name = "VAULT_PATH")]
        vault: PathBuf,
    },
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
        Commands::Delete { vault } => vault::delete_vault(&vault),
        Commands::Log { vault } => vault::log_vault(&vault),
    }
}