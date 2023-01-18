use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use secstr::SecUtf8;

use crate::{packet::Packet, store::Credential};

pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Creates a new client instances.
    /// # Errors
    /// Can fail due to I/O errors, most likely the path does not exist.
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Ok(Self {
            stream: UnixStream::connect(path)?,
        })
    }

    /// Sends an unlock store request and handles the response.
    /// # Errors
    /// Can fail if the message is too long or I/O erros are encountered.
    pub fn unlock(
        &mut self,
        passphrase: SecUtf8,
        store_path: PathBuf,
        timeout: u64,
    ) -> Result<(), crate::Error> {
        crate::packet::write(
            &mut self.stream,
            &Packet::Unlock {
                passphrase,
                timeout,
                store_path,
            },
        )?;
        let response = crate::packet::parse(&mut self.stream)?;
        if let Packet::Result { message, success } = response {
            if !success {
                eprintln!("Unlocking failed. It is likely that a wrong passphrase was entered. Received from daemon: {message}");
            }
        } else {
            eprintln!("Received an unexpected return value from daemon.");
        }
        Ok(())
    }

    /// Sends a lock store request.
    /// # Errors
    /// Can fail if the message is too long or I/O erros are encountered.
    pub fn lock(&mut self) -> Result<(), crate::Error> {
        crate::packet::write(&mut self.stream, &Packet::Lock)
    }

    /// Sends the credential to store it and handles the response.
    /// # Errors
    // Can fail if the message is too long or I/O erros are encountered.
    pub fn store(&mut self, credential: Credential) -> Result<(), crate::Error> {
        crate::packet::write(&mut self.stream, &Packet::Store { credential })?;
        let response = crate::packet::parse(&mut self.stream)?;
        if let Packet::Result { message, success } = response {
            if !success {
                eprintln!("Storing the credential failed. You may need to `nicator unlock`. Received from daemon: {message}");
            }
        } else {
            eprintln!("Received an unexpected return value from daemon.");
        }
        Ok(())
    }

    /// Fetches a credential from the store and returns the found credential if any.
    /// # Errors
    /// Can fail if the message is too long or I/O erros are encountered.
    pub fn get(&mut self, credential: Credential) -> Result<Option<Credential>, crate::Error> {
        crate::packet::write(&mut self.stream, &Packet::Get { credential })?;
        let response = crate::packet::parse(&mut self.stream)?;
        match response {
            Packet::Get { credential } => return Ok(Some(credential)),
            Packet::Result { message, .. } => {
                eprintln!(
                    "Failed to fetch credential from the nicator store. You may need to `nicator unlock`. Received from daemon: {}",
                    message
                );
            }
            _ => {}
        }
        Ok(None)
    }

    /// Sends a request to delete a credential from the store and handles the response.
    /// # Errors
    /// Can fail if the message is too long or I/O erros are encountered.
    pub fn erase(&mut self, credential: Credential) -> Result<(), crate::Error> {
        crate::packet::write(&mut self.stream, &Packet::Erase { credential })?;
        let response = crate::packet::parse(&mut self.stream)?;
        if let Packet::Result { message, success } = response {
            if !success {
                eprintln!(
                    "Erase failed. You may need to `nicator unlock`. Received from daemon: {}",
                    message
                );
            }
        } else {
            eprintln!("Received an unexpected return value from daemon.");
        }
        Ok(())
    }
}
