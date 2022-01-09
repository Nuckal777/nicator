use std::{io::Read, path::PathBuf};

use clap::{crate_authors, crate_version, App, Arg, ArgMatches, SubCommand};
use client::Client;
use secstr::SecUtf8;
use thiserror::Error;

pub mod client;
mod packet;
pub mod server;
pub mod store;

const STORE_FILE_NAME: &str = ".nicator-credentials";
const DEFAULT_TIMEOUT: u64 = 3600;

pub enum Exit {
    Success = 0,
    Failure = 1,
}

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
    #[error("Found no user object.")]
    NoUser,
    #[error("Some string conversion failed due to invalid utf8.")]
    Utf(#[from] std::str::Utf8Error),
}

struct ProgramOptions {
    timeout: u64,
    store: PathBuf,
    socket: PathBuf,
    git_credentials: PathBuf,
}

impl ProgramOptions {
    fn from_matches(
        global: &ArgMatches,
        sub: Option<&ArgMatches>,
    ) -> Result<ProgramOptions, Error> {
        let uid = nix::unistd::getuid();
        let user = nix::unistd::User::from_uid(uid)?.ok_or(Error::NoUser)?;
        Ok(ProgramOptions {
            git_credentials: Self::get_git_cred_path(sub, &user),
            store: Self::get_store_path(global, &user),
            socket: Self::get_socket_path(global),
            timeout: sub
                .map_or(Ok(DEFAULT_TIMEOUT), |m| {
                    m.value_of("timeout")
                        .map_or(Ok(DEFAULT_TIMEOUT), str::parse)
                })
                .map_err(|_| Error::Conversion)?,
        })
    }

    fn get_git_cred_path(matches: Option<&ArgMatches>, user: &nix::unistd::User) -> PathBuf {
        if let Some(matches) = matches {
            if let Some(path) = matches.value_of("git") {
                return PathBuf::from(path);
            }
        }
        let mut git_cred_path = user.dir.clone();
        git_cred_path.push(".git-credentials");
        git_cred_path
    }

    fn get_store_path(matches: &ArgMatches, user: &nix::unistd::User) -> PathBuf {
        if let Some(path) = matches.value_of("credentials") {
            return PathBuf::from(path);
        }
        let mut store_path = user.dir.clone();
        store_path.push(STORE_FILE_NAME);
        store_path
    }

    fn get_socket_path(matches: &ArgMatches) -> PathBuf {
        if let Some(path) = matches.value_of("socket") {
            return PathBuf::from(path);
        }
        let uid = nix::unistd::getuid();
        let file_name = format!("/tmp/nicator-{}.sock", uid);
        PathBuf::from(file_name)
    }
}

#[must_use]
pub fn run() -> Exit {
    let matches = App::new("nicator")
        .version(crate_version!())
        .author(crate_authors!())
        .about("A lightweight encrypting git credential helper")
        .subcommands(vec![
            SubCommand::with_name("server").about("Starts nicator server daemon. Nicator does this automatically while unlocking."),
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
            SubCommand::with_name("export").about("Prints out all stored credentials."),
            SubCommand::with_name("import").about("Imports a .git-credentials into the nicator store.").arg(
                Arg::with_name("git")
                    .short("g")
                    .long("git")
                    .help("Path to .git-credentials. Defaults to ~/.git-credentials")
                    .value_name("PATH")
                    .takes_value(true)
            ),
        ])
        .args(&[
            Arg::with_name("socket")
                .short("s")
                .long("socket")
                .help("Path used for the unix socket. Defaults to '/tmp/nicator-$UID.sock'. Non-default values screw up git integration.")
                .value_name("PATH")
                .takes_value(true),
            Arg::with_name("credentials")
                .short("c")
                .long("credentials")
                .help("Path to the credential store. Defaults to '$HOME/.nicator-credentials'.")
                .value_name("PATH")
                .takes_value(true),
        ])
        .get_matches();

    let (name, sub_matches) = matches.subcommand();
    let options = ProgramOptions::from_matches(&matches, sub_matches);
    match options {
        Ok(options) => perform_command(name, options),
        Err(err) => {
            eprintln!("Failed to determine arguments. {}", err);
            Exit::Failure
        }
    }
}

fn perform_command(command: &str, options: ProgramOptions) -> Exit {
    match command {
        "server" => return perform_server(options),
        "init" => return perform_init(&options),
        "lock" => return perform_lock(&options),
        "unlock" => return perform_unlock(&options),
        "store" => return perform_store(&options),
        "get" => return perform_get(&options),
        "erase" => return perform_erase(&options),
        "export" => return perform_export(&options),
        "import" => return perform_import(&options),
        _ => eprintln!("Unknown operation."),
    };
    Exit::Failure
}

fn perform_server(options: ProgramOptions) -> Exit {
    let abs_socket = if options.socket.is_absolute() {
        options.socket
    } else {
        std::env::current_dir()
            .expect("Failed to fetch working directory.")
            .join(options.socket)
    };
    nix::unistd::daemon(false, false).expect("Failed to daemonize nicator.");
    server::launch(abs_socket).expect("Failed to launch the nicator server daemon.");
    Exit::Success
}

fn perform_init(options: &ProgramOptions) -> Exit {
    if options.store.exists() {
        eprintln!(
            "A credentials file already exists at {:?}. Not overwriting.",
            options.store
        );
        return Exit::Failure;
    }
    let passphrase = SecUtf8::from(
        rpassword::prompt_password_stdout("Enter passphrase: ")
            .expect("Failed to read passphrase from stdin."),
    );
    let store = store::Store::default();
    store
        .encrypt_at(&options.store, passphrase.unsecure())
        .expect("Failed to create .nicator-credentials file.");
    Exit::Success
}

fn perform_lock(options: &ProgramOptions) -> Exit {
    with_client(options, |client| {
        client.lock().expect("Failed to lock the nicator store");
    })
}

fn perform_unlock(options: &ProgramOptions) -> Exit {
    if !options.socket.exists() {
        let nicator_path =
            std::env::current_exe().expect("Failed to fetch path for nicator binary.");
        std::process::Command::new(nicator_path)
            .arg("-s")
            .arg(&options.socket)
            .arg("server")
            .spawn()
            .expect("Failed to create nicator damon spawn process.");
    }
    std::thread::sleep(std::time::Duration::from_millis(50));

    let store_path = std::fs::canonicalize(&options.store);
    match store_path {
        Ok(store_path) => with_client(options, |client| {
            let passphrase = SecUtf8::from(
                rpassword::prompt_password_stdout("Enter passphrase: ")
                    .expect("Failed to read passphrase from stdin."),
            );
            client
                .unlock(passphrase, store_path, options.timeout)
                .expect("Failed to unlock the nicator store.");
        }),
        Err(err) => {
            eprintln!(
                "Failed to canonicalize store path {:?}: {}",
                options.store, err
            );
            Exit::Failure
        }
    }
}

fn perform_store(options: &ProgramOptions) -> Exit {
    let mut data = Vec::<u8>::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .expect("Failed to read credential from stdin.");
    let git_credential = String::from_utf8(data).expect("Credential is invalid Utf8.");
    let credential = store::Credential::from_git(&git_credential);
    with_client(options, |client| {
        client
            .store(credential)
            .expect("Failed to store the credential.");
    })
}

fn perform_get(options: &ProgramOptions) -> Exit {
    let mut data = Vec::<u8>::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .expect("Failed to read credential from stdin.");
    let git_credential = String::from_utf8(data).expect("Credential is invalid Utf8.");
    let credential = store::Credential::from_git(&git_credential);
    with_client(options, |client| {
        let opt_result = client
            .get(credential)
            .expect("Failed to fetch the credential.");
        if let Some(result) = opt_result {
            println!("username={}", result.username);
            println!("password={}", result.password.unsecure());
        }
    })
}

fn perform_erase(options: &ProgramOptions) -> Exit {
    let mut data = Vec::<u8>::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .expect("Failed to read credential from stdin.");
    let git_credential = String::from_utf8(data).expect("Credential is invalid Utf8.");
    let credential = store::Credential::from_git(&git_credential);
    with_client(options, |client| {
        client
            .erase(credential)
            .expect("Failed to erase the credential.");
    })
}

fn perform_export(options: &ProgramOptions) -> Exit {
    let passphrase = SecUtf8::from(
        rpassword::prompt_password_stdout("Enter passphrase: ")
            .expect("Failed to read passphrase from stdin."),
    );
    let store = store::Store::decrypt_from(&options.store, passphrase.unsecure());
    match store {
        Ok(store) => {
            for cred in store.iter() {
                println!("protocol={}", cred.protocol);
                println!("host={}", cred.host);
                println!("path={}", cred.path);
                println!("username={}", cred.username);
                println!("password={}", cred.password.unsecure());
            }
        }
        Err(err) => {
            eprintln!("Failed to export credentials: {}", err);
            return Exit::Failure;
        }
    }
    Exit::Success
}

fn perform_import(options: &ProgramOptions) -> Exit {
    let passphrase = SecUtf8::from(
        rpassword::prompt_password_stdout("Enter passphrase: ")
            .expect("Failed to read passphrase from stdin."),
    );
    let git_credentials = std::fs::read_to_string(&options.git_credentials).map(SecUtf8::from);
    if git_credentials.is_err() {
        eprintln!("Failed to open .git-credentials");
        return Exit::Failure;
    }
    let credentials: Result<Vec<store::Credential>, url::ParseError> = git_credentials
        .unwrap()
        .unsecure()
        .lines()
        .filter_map(|s| {
            if s.is_empty() {
                None
            } else {
                Some(store::Credential::from_url(s))
            }
        })
        .collect();
    if credentials.is_err() {
        eprintln!("Failed to parse .git-credentials file.");
        return Exit::Failure;
    }
    let store = store::Store::decrypt_from(&options.store, passphrase.unsecure());
    match store {
        Ok(mut store) => {
            for cred in credentials.unwrap() {
                store.update(cred);
            }
            match store.encrypt_at(&options.store, passphrase.unsecure()) {
                Ok(_) => Exit::Success,
                Err(err) => {
                    eprintln!("Failed to store imported credentials. {}", err);
                    Exit::Failure
                }
            }
        }
        Err(err) => {
            eprintln!("Failed to import credentials: {}", err);
            Exit::Failure
        }
    }
}

fn with_client<H: FnOnce(&mut Client)>(options: &ProgramOptions, handler: H) -> Exit {
    if let Ok(mut client) = Client::new(&options.socket) {
        handler(&mut client);
        return Exit::Success;
    }
    eprintln!("Failed to connect to the nicator server daemon. Cannot find socket file. You may need to `nicator unlock`.");
    Exit::Failure
}
