use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{net::Shutdown, path::Path};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

const POLL_TIMEOUT: i32 = 200;

use secstr::SecUtf8;

use crate::{
    packet::{parse, Packet},
    store::{self, Credential},
};

struct Daemon {
    listener: UnixListener,
    passphrase: Option<SecUtf8>,
    // in seconds
    timeout: Duration,
    store_path: PathBuf,
}

impl Daemon {
    fn new<P: AsRef<Path>>(socket_path: P) -> std::io::Result<Daemon> {
        Ok(Self {
            listener: UnixListener::bind(socket_path)?,
            passphrase: None,
            // default to 1 sec so the daemon shutsdown if unlocking fails
            timeout: Duration::from_secs(1),
            store_path: PathBuf::new(),
        })
    }

    fn main_loop<P: AsRef<Path>>(&mut self, socket_path: P) -> Result<(), crate::Error> {
        let terminate = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate.clone())?;
        let start_time = Instant::now();
        while !terminate.load(Ordering::Relaxed) {
            let perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(socket_path.as_ref(), perm)?;
            if self.poll()? {
                let exit = self.accept()?;
                if exit {
                    break;
                }
            }
            let current_time = Instant::now();
            let duration = current_time - start_time;
            if duration > self.timeout {
                break;
            }
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<bool, crate::Error> {
        let poll_fd =
            nix::poll::PollFd::new(self.listener.as_raw_fd(), nix::poll::PollFlags::POLLIN);
        let poll_count = nix::poll::poll(&mut [poll_fd], POLL_TIMEOUT)?;
        Ok(poll_count == 1)
    }

    fn accept(&mut self) -> Result<bool, crate::Error> {
        let mut should_exit = false;
        let (mut conn, _) = self.listener.accept()?;
        let request = parse(&mut conn)?;
        match request {
            Packet::Lock => should_exit = true,
            Packet::Unlock {
                passphrase,
                timeout,
                store_path,
            } => self.handle_unlock(&mut conn, store_path, passphrase, timeout)?,
            Packet::Store { credential } => self.handle_store(&mut conn, credential)?,
            Packet::Get { credential } => self.handle_get(&mut conn, &credential)?,
            Packet::Erase { credential } => self.handle_erase(&mut conn, &credential)?,
            Packet::Result { .. } => {}
        }
        conn.shutdown(Shutdown::Both)?;
        Ok(should_exit)
    }

    fn respond_store_locked(conn: &mut UnixStream) -> Result<(), crate::Error> {
        let response = Packet::Result {
            message: "Store is locked.".to_string(),
            success: false,
        };
        crate::packet::write(conn, &response)
    }

    fn handle_unlock(
        &mut self,
        conn: &mut UnixStream,
        store_path: PathBuf,
        passphrase: SecUtf8,
        timeout: u64,
    ) -> Result<(), crate::Error> {
        // try to unlock
        self.store_path = store_path;
        let store = store::Store::decrypt_from(&self.store_path, passphrase.unsecure());
        match store {
            Ok(_) => {
                self.passphrase = Some(passphrase);
                self.timeout = Duration::from_secs(timeout);
                let response = Packet::Result {
                    message: "".to_string(),
                    success: true,
                };
                crate::packet::write(conn, &response)?;
            }
            Err(err) => {
                let response = Packet::Result {
                    message: format!("{}", err),
                    success: false,
                };
                crate::packet::write(conn, &response)?;
            }
        }
        Ok(())
    }

    fn handle_store(
        &mut self,
        conn: &mut UnixStream,
        credential: Credential,
    ) -> Result<(), crate::Error> {
        if self.passphrase.is_some() {
            let result = Self::store(
                credential,
                self.passphrase.as_ref().unwrap().unsecure(),
                &self.store_path,
            );
            match result {
                Ok(_) => {
                    let response = Packet::Result {
                        message: "".to_string(),
                        success: true,
                    };
                    crate::packet::write(conn, &response)?;
                }
                Err(err) => {
                    let response = Packet::Result {
                        message: format!("{}", err),
                        success: false,
                    };
                    crate::packet::write(conn, &response)?;
                }
            }
        } else {
            Self::respond_store_locked(conn)?;
        }
        Ok(())
    }

    fn store(credential: Credential, passphrase: &str, path: &Path) -> Result<(), crate::Error> {
        let mut store = store::Store::decrypt_from(path, passphrase)?;
        store.update(credential);
        store.encrypt_at(path, passphrase)?;
        Ok(())
    }

    fn handle_get(
        &mut self,
        conn: &mut UnixStream,
        credential: &Credential,
    ) -> Result<(), crate::Error> {
        if self.passphrase.is_some() {
            let result = Self::get(
                credential,
                self.passphrase.as_ref().unwrap().unsecure(),
                &self.store_path,
            );
            match result {
                Ok(opt_credential) => {
                    if let Some(some_credential) = opt_credential {
                        let response = Packet::Get {
                            credential: some_credential,
                        };
                        crate::packet::write(conn, &response)?;
                    } else {
                        let response = Packet::Result {
                            message: "No matching credential.".to_string(),
                            success: true,
                        };
                        crate::packet::write(conn, &response)?;
                    }
                }
                Err(err) => {
                    let response = Packet::Result {
                        message: format!("{}", err),
                        success: false,
                    };
                    crate::packet::write(conn, &response)?;
                }
            }
        } else {
            Self::respond_store_locked(conn)?;
        }
        Ok(())
    }

    fn get(
        credential: &Credential,
        passphrase: &str,
        path: &Path,
    ) -> Result<Option<Credential>, crate::Error> {
        let store = store::Store::decrypt_from(path, passphrase)?;
        Ok(store.find(&credential.protocol, &credential.host, &credential.path))
    }

    fn handle_erase(
        &mut self,
        conn: &mut UnixStream,
        credential: &Credential,
    ) -> Result<(), crate::Error> {
        if self.passphrase.is_some() {
            let result = Self::erase(
                credential,
                self.passphrase.as_ref().unwrap().unsecure(),
                &self.store_path,
            );
            match result {
                Ok(_) => {
                    let response = Packet::Result {
                        message: "".to_string(),
                        success: true,
                    };
                    crate::packet::write(conn, &response)?;
                }
                Err(err) => {
                    let response = Packet::Result {
                        message: format!("{}", err),
                        success: false,
                    };
                    crate::packet::write(conn, &response)?;
                }
            }
        } else {
            Self::respond_store_locked(conn)?;
        }
        Ok(())
    }

    fn erase(credential: &Credential, passphrase: &str, path: &Path) -> Result<(), crate::Error> {
        let mut store = store::Store::decrypt_from(path, passphrase)?;
        store.erase(&credential.protocol, &credential.host, &credential.path);
        store.encrypt_at(path, passphrase)?;
        Ok(())
    }
}

/// Takes control of the current thread and runs a nicator server listening on the given path.
/// # Errors
/// Can fail due to I/O and filesystem related errors.
pub fn launch<P: AsRef<Path>>(socket_path: P) -> Result<(), crate::Error> {
    // sanity check if there is already daemon listening
    if socket_path.as_ref().exists() {
        println!("A nicator daemon is already running.");
        return Ok(());
    }
    let mut daemon = Daemon::new(&socket_path)?;
    match daemon.main_loop(socket_path.as_ref()) {
        Ok(_) => println!("nicator server exiting"),
        Err(err) => eprintln!("nicator server had an error: {}", err),
    }
    std::fs::remove_file(socket_path)?;
    Ok(())
}
