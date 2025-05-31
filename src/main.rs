use std::env;
use std::path::Path;
use std::io;
mod vault;
use rpassword::read_password;
use vault::vault::Vault;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("vault new <vault_dir> <vault_name>");
        eprintln!("vault add -f <file> -v <vault_file>");
        eprintln!("vault extract -f <file> -v <vault_file>");
        eprintln!("vault rem -f <file> -v <vault_file>");
        eprintln!("vault remex -f <file> -v <vault_file> -o <output>");
        eprintln!("vault log -v <vault_file>");
        return Ok(());
    }

    match args[1].as_str() {
        "new" => {
            let dir = Path::new(&args[2]);
            let name = &args[3];
            println!("Set password for new vault:");
            let password = read_password().unwrap();
            Vault::new(dir, name, &password)?;
        }
        "add" => {
            let file = Path::new(&args[3]);
            let vault_path = Path::new(&args[5]);
            println!("Enter password:");
            let password = read_password().unwrap();
            let mut vault = Vault::open(vault_path, &password)?;
            vault.add_file(file)?;
        }
        "extract" => {
            let file = &args[3];
            let vault_path = Path::new(&args[5]);
            println!("Enter password:");
            let password = read_password().unwrap();
            let vault = Vault::open(vault_path, &password)?;
            vault.extract_file(file, Path::new(file))?;
        }
        "rem" => {
            let file = &args[3];
            let vault_path = Path::new(&args[5]);
            println!("Enter password:");
            let password = read_password().unwrap();
            let mut vault = Vault::open(vault_path, &password)?;
            vault.remove_file(file)?;
        }
        "remex" => {
            let file = &args[3];
            let vault_path = Path::new(&args[5]);
            let output_path = Path::new(&args[7]);
            println!("Enter password:");
            let password = read_password().unwrap();
            let mut vault = Vault::open(vault_path, &password)?;
            vault.remove_and_extract(file, output_path)?;
        }
        "log" => {
            let vault_path = Path::new(&args[3]);
            println!("Enter password:");
            let password = read_password().unwrap();
            let vault = Vault::open(vault_path, &password)?;
            vault.show_log()?;
        }
        _ => {
            eprintln!("Unknown command.");
        }
    }

    Ok(())

}