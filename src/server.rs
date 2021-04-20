use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::{net::Shutdown, path::Path};

use crate::{
    get_store_path,
    packet::{parse, Packet},
    store::{self, Credential},
};

struct Daemon {
    listener: UnixListener,
    passphrase: Option<String>,
}

impl Daemon {
    fn new() -> std::io::Result<Daemon> {
        Ok(Self {
            listener: UnixListener::bind(crate::SOCKET_PATH)?,
            passphrase: None,
        })
    }

    fn listen(&mut self) -> Result<bool, crate::Error> {
        let mut should_exit = false;
        let (mut conn, _) = self.listener.accept()?;
        let request = parse(&mut conn)?;
        match request {
            Packet::Lock => should_exit = true,
            Packet::Unlock { passphrase } => self.handle_unlock(&mut conn, passphrase)?,
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
        passphrase: String,
    ) -> Result<(), crate::Error> {
        // try to unlock
        let store = store::Store::decrypt_from(&get_store_path(), &passphrase);
        match store {
            Ok(_) => {
                self.passphrase = Some(passphrase);
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
            let result = Self::store(credential, self.passphrase.as_ref().unwrap());
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

    fn store(credential: Credential, passphrase: &str) -> Result<(), crate::Error> {
        let mut store = store::Store::decrypt_from(&get_store_path(), passphrase)?;
        store.credentials.push(credential);
        store.encrypt_at(&get_store_path(), passphrase)?;
        Ok(())
    }

    fn handle_get(
        &mut self,
        conn: &mut UnixStream,
        credential: &Credential,
    ) -> Result<(), crate::Error> {
        if self.passphrase.is_some() {
            let result = Self::get(credential, self.passphrase.as_ref().unwrap());
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

    fn get(credential: &Credential, passphrase: &str) -> Result<Option<Credential>, crate::Error> {
        let store = store::Store::decrypt_from(&get_store_path(), passphrase)?;
        Ok(store.find(&credential.protocol, &credential.host, &credential.path))
    }

    fn handle_erase(
        &mut self,
        conn: &mut UnixStream,
        credential: &Credential,
    ) -> Result<(), crate::Error> {
        if self.passphrase.is_some() {
            let result = Self::erase(credential, self.passphrase.as_ref().unwrap());
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

    fn erase(credential: &Credential, passphrase: &str) -> Result<(), crate::Error> {
        let mut store = store::Store::decrypt_from(&get_store_path(), passphrase)?;
        store.erase(&credential.protocol, &credential.host, &credential.path);
        store.encrypt_at(&get_store_path(), passphrase)?;
        Ok(())
    }
}

pub fn launch() -> Result<(), crate::Error> {
    // sanity check if there is already daemon listening
    if Path::new(crate::SOCKET_PATH).exists() {
        println!("A nicator daemon is already running.");
        return Ok(());
    }
    nix::unistd::daemon(false, false)?;
    let mut daemon = Daemon::new()?;
    let perm = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(crate::SOCKET_PATH, perm)?;
    loop {
        let exit = daemon.listen()?;
        if exit {
            break;
        }
    }
    std::fs::remove_file(crate::SOCKET_PATH)?;
    Ok(())
}