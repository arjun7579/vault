mod compress;
mod crypto;
mod log;
mod vault;

use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vault")]
#[command(about = "A secure encrypted file vault with compression and logging.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault
    New {
        /// Directory to place the vault
        vault_directory: PathBuf,
        /// Name of the vault
        vault_name: String,
    },

    /// Add a file to the vault
    Add {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short, long)]
        vault: PathBuf,
    },

    /// Extract a file from the vault
    Extract {
        #[arg(short, long)]
        file: String,
        #[arg(short, long)]
        vault: PathBuf,
    },

    /// Remove a file from the vault
    Rem {
        #[arg(short, long)]
        file: String,
        #[arg(short, long)]
        vault: PathBuf,
    },

    /// Extract and then remove a file
    Remex {
        #[arg(short, long)]
        file: String,
        #[arg(short, long)]
        vault: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Show operation log for the vault
    Log {
        #[arg(short, long)]
        vault: PathBuf,
    },
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::New { vault_directory, vault_name } => {
            vault::create_vault(&vault_directory, &vault_name)?;
        }

        Commands::Add { file, vault } => {
            vault::add_file(&file, &vault)?;
        }

        Commands::Extract { file, vault } => {
            vault::extract_file(&file, &vault)?;
        }

        Commands::Rem { file, vault } => {
            vault::remove_file(&file, &vault)?;
        }

        Commands::Remex { file, vault, output } => {
            vault::remex_file(&file, &vault, &output)?;
        }

        Commands::Log { vault } => {
            let path = vault.with_extension("log");
            log::print_log(&path)?;
        }
    }

    Ok(())
}
