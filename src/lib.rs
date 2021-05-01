use std::{io::Read, path::PathBuf};

use clap::{crate_authors, crate_version, App, Arg, ArgMatches, SubCommand};
use client::Client;
use thiserror::Error;

pub mod client;
mod packet;
pub mod server;
pub mod store;

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

pub fn run() {
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
            nix::unistd::daemon(false, false).expect("Failed to daemonize nicator.");
            server::launch(&get_socket_path())
                .expect("Failed to launch the nicator server daemon.");
        }
        "init" => {
            let store_path = get_store_path().expect("Failed to determine store path.");
            if store_path.exists() {
                eprintln!(
                    "A credentials file already exists at {:?}. Not overwriting.",
                    store_path
                );
                return;
            }
            let passphrase = rpassword::prompt_password_stdout("Enter passphrase: ")
                .expect("Failed to read passphrase from stdin.");
            let store = store::Store::default();
            store
                .encrypt_at(&store_path, &passphrase)
                .expect("Failed to create .nicator-credentials file.");
        }
        "lock" => {
            if let Some(mut client) = create_client() {
                client.lock().expect("Failed to lock the nicator store");
            }
        }
        "unlock" => {
            if !get_socket_path().exists() {
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
                            .unlock(
                                passphrase,
                                get_store_path().expect("Failed to determine store path."),
                                timeout,
                            )
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
                let opt_result = client
                    .get(credential)
                    .expect("Failed to fetch the credential.");
                if let Some(result) = opt_result {
                    println!("username={}", result.username);
                    println!("password={}", result.password);
                }
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

fn get_store_path() -> Result<PathBuf, crate::Error> {
    let uid = nix::unistd::getuid();
    let user = nix::unistd::User::from_uid(uid)?;
    let mut store_path = user.expect("Cannot get user from process uid.").dir;
    store_path.push(STORE_FILE_NAME);
    Ok(store_path)
}

fn get_socket_path() -> PathBuf {
    let uid = nix::unistd::getuid();
    let file_name = format!("/tmp/nicator-{}.sock", uid);
    PathBuf::from(file_name)
}

fn create_client() -> Option<Client> {
    if let Ok(client) = Client::new(&get_socket_path()) {
        return Some(client);
    }
    eprintln!("Failed to connect to the nicator server daemon. Cannot find socket file. You may need to `nicator unlock`.");
    None
}
