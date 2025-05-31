use clap::{Parser, Subcommand};
mod vault;
mod utils;

#[derive(Parser)]
#[command(name = "vault")]
#[command(about = "Encrypted file vault CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    New {
        location: String,
        vault_name: String,
    },
    Add {
        #[arg(short = 'f', long)]
        filename: String,

        #[arg(short = 'v', long)]
        vault: String,
    },
    Extract {
        #[arg(short = 'f', long)]
        filename: Option<String>, // None means extract all

        #[arg(short = 'v', long)]
        vault: String,
    },
    Rem {
        #[arg(short = 'f', long)]
        filename: String,

        #[arg(short = 'v', long)]
        vault: String,
    },
    Remex {
        #[arg(short = 'f', long)]
        filename: String,

        #[arg(short = 'v', long)]
        vault: String,

        #[arg(short = 'o', long)]
        output: String,
    },
    Log {
        #[arg(short = 'v', long)]
        vault: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::New { location, vault_name } => {
            let path = std::path::Path::new(location).join(format!("{vault_name}.vlt"));
            let password = utils::read_password_prompt("Enter new vault password: ")?;
            let mut vault = vault::Vault::new(&path, &password)?;
            println!("Vault created at {:?}", path);
        }
        Commands::Add { filename, vault } => {
            let password = utils::read_password_prompt("Enter vault password: ")?;
            let mut vault = vault::Vault::open(vault, &password)?;
            vault.add_file(filename)?;
            println!("Added file {filename} to vault {vault}");
        }
        Commands::Extract { filename, vault } => {
            let password = utils::read_password_prompt("Enter vault password: ")?;
            let mut vault = vault::Vault::open(vault, &password)?;
            if let Some(file) = filename {
                vault.extract_file(file, std::path::Path::new("."))?;
                println!("Extracted {file}");
            } else {
                vault.extract_all(std::path::Path::new("."))?;
                println!("Extracted all files");
            }
        }
        Commands::Rem { filename, vault } => {
            let password = utils::read_password_prompt("Enter vault password: ")?;
            let mut vault = vault::Vault::open(vault, &password)?;
            vault.remove_file(filename)?;
            println!("Removed {filename} from vault {vault}");
        }
        Commands::Remex { filename, vault, output } => {
            let password = utils::read_password_prompt("Enter vault password: ")?;
            let mut vault = vault::Vault::open(vault, &password)?;
            vault.remove_and_extract_file(filename, std::path::Path::new(output))?;
            println!("Removed and extracted {filename} to {output}");
        }
        Commands::Log { vault } => {
            let password = utils::read_password_prompt("Enter vault password: ")?;
            let vault = vault::Vault::open(vault, &password)?;
            vault.show_log()?;
        }
    }

    Ok(())
}
