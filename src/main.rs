use std::{
    io::Read,
    path::{Path, PathBuf},
};

use clap::{crate_authors, crate_version, App, Arg, ArgMatches, SubCommand};
use client::Client;
use thiserror::Error;

mod client;
mod packet;
mod server;
mod store;

const SOCKET_PATH: &str = "/tmp/nicator.sock";
const STORE_FILE_NAME: &str = ".nicator-credentials";
const DEFAULT_TIMEOUT: u64 = 3600;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Some unix socket operation failed.")]
    Socket(#[from] std::io::Error),
    #[error("Some unix api call failed.")]
    Unix(#[from] nix::Error),
    #[error("Some de-/serialization failed.")]
    Bincode(#[from] bincode::Error),
    #[error("Some number conversion failed.")]
    Conversion,
    #[error("Some cryptography failed.")]
    Crypto,
}

fn main() {
    let matches = App::new("nicator")
        .version(crate_version!())
        .author(crate_authors!())
        .about("A lightweight encrypting git credential helper")
        .subcommands(vec![
            SubCommand::with_name("server").about("Starts nicator server daemon. Nicator does this acutomatically while unlocking."),
            SubCommand::with_name("init").about("Creates the .nicator-credentials file."),
            SubCommand::with_name("lock").about("Locks access to the nicator store by shutting down the server daemon."),
            SubCommand::with_name("unlock").about("Unlocks the nicator store. Starts a server daemon if required.").arg(
                Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .help("Timeout after which to lock the store. Defaults to 3600s.")
                .value_name("SECONDS")
                .takes_value(true)),
            SubCommand::with_name("get").about("Fetches a credential from the nicator store. Required information is read from stdin according to the git credentials format."),
            SubCommand::with_name("store").about("Stores a credential in the nicator store. Required information is read from stdin according to the git credentials format."),
            SubCommand::with_name("erase").about("Deletes a credential from the nicator store. Required information is read from stdin according to the git credentials format."),
            SubCommand::with_name("export"),
        ])
        .get_matches();

    let (name, sub_matches) = matches.subcommand();
    perform_command(name, sub_matches);
}

fn perform_command(command: &str, matches: Option<&ArgMatches>) {
    match command {
        "server" => {
            server::launch().expect("Failed to launch the nicator server daemon.");
        }
        "init" => {
            let passphrase = rpassword::prompt_password_stdout("Enter passphrase: ")
                .expect("Failed to read passphrase from stdin.");
            let store = store::Store::default();
            store
                .encrypt_at(&get_store_path(), &passphrase)
                .expect("Failed to create .nicator-credentials file.");
        }
        "lock" => {
            if let Some(mut client) = create_client() {
                client.lock().expect("Failed to lock the nicator store");
            }
        }
        "unlock" => {
            if !Path::new(SOCKET_PATH).exists() {
                std::process::Command::new("nicator")
                    .arg("server")
                    .spawn()
                    .expect("Failed to create nicator damon spawn process.");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            let timeout = matches.map_or(Ok(DEFAULT_TIMEOUT), |m| {
                m.value_of("timeout")
                    .map_or(Ok(DEFAULT_TIMEOUT), str::parse)
            });
            match timeout {
                Ok(timeout) => {
                    if let Some(mut client) = create_client() {
                        let passphrase = rpassword::prompt_password_stdout("Enter passphrase: ")
                            .expect("Failed to read passphrase from stdin.");
                        client
                            .unlock(passphrase, timeout)
                            .expect("Failed to unlock the nicator store.")
                    }
                }
                Err(_) => eprintln!("Failed to parse timeout."),
            }
        }
        "store" => {
            let mut data = Vec::<u8>::new();
            std::io::stdin()
                .read_to_end(&mut data)
                .expect("Failed to read credential from stdin.");
            let git_credential = String::from_utf8(data).expect("Credential is invalid Utf8.");
            let credential = store::Credential::from_git(&git_credential);
            if let Some(mut client) = create_client() {
                client
                    .store(credential)
                    .expect("Failed to store the credential.");
            }
        }
        "get" => {
            let mut data = Vec::<u8>::new();
            std::io::stdin()
                .read_to_end(&mut data)
                .expect("Failed to read credential from stdin.");
            let git_credential = String::from_utf8(data).expect("Credential is invalid Utf8.");
            let credential = store::Credential::from_git(&git_credential);
            if let Some(mut client) = create_client() {
                client
                    .get(credential)
                    .expect("Failed to fetch the credential.");
            }
        }
        "erase" => {
            let mut data = Vec::<u8>::new();
            std::io::stdin()
                .read_to_end(&mut data)
                .expect("Failed to read credential from stdin.");
            let git_credential = String::from_utf8(data).expect("Credential is invalid Utf8.");
            let credential = store::Credential::from_git(&git_credential);
            if let Some(mut client) = create_client() {
                client
                    .erase(credential)
                    .expect("Failed to erase the credential.");
            }
        }
        _ => println!("Unknown operation."),
    }
}

fn get_store_path() -> PathBuf {
    let home = std::env::var("HOME").expect("Could not determine $HOME for user.");
    let home_path = Path::new(&home);
    let mut store_path = home_path.to_path_buf();
    store_path.push(STORE_FILE_NAME);
    store_path
}

fn create_client() -> Option<Client> {
    if let Ok(client) = Client::new(SOCKET_PATH) {
        return Some(client);
    }
    eprintln!("Failed to connect to the nicator server daemon. Cannot find socket file. You may need to `nicator unlock`.");
    None
}
