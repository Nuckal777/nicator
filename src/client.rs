use std::{os::unix::net::UnixStream, path::Path};

use crate::{packet::Packet, store::Credential};

pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Ok(Self {
            stream: UnixStream::connect(path)?,
        })
    }

    pub fn unlock(&mut self, passphrase: String, timeout: u64) -> Result<(), crate::Error> {
        crate::packet::write(
            &mut self.stream,
            &Packet::Unlock {
                passphrase,
                timeout,
            },
        )?;
        let response = crate::packet::parse(&mut self.stream)?;
        if let Packet::Result { message, success } = response {
            if !success {
                eprintln!("Unlocking failed. It is likely that a wrong passphrase was entered. Received from daemon: {}", message);
            }
        } else {
            eprintln!("Received an unexpected return value from daemon.");
        }
        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), crate::Error> {
        crate::packet::write(&mut self.stream, &Packet::Lock)
    }

    pub fn store(&mut self, credential: Credential) -> Result<(), crate::Error> {
        crate::packet::write(&mut self.stream, &Packet::Store { credential })?;
        let response = crate::packet::parse(&mut self.stream)?;
        if let Packet::Result { message, success } = response {
            if !success {
                eprintln!("Storing the credential failed. You may need to `nicator unlock`. Received from daemon: {}", message);
            }
        } else {
            eprintln!("Received an unexpected return value from daemon.");
        }
        Ok(())
    }

    pub fn get(&mut self, credential: Credential) -> Result<(), crate::Error> {
        crate::packet::write(&mut self.stream, &Packet::Get { credential })?;
        let response = crate::packet::parse(&mut self.stream)?;
        match response {
            Packet::Get { credential } => {
                println!("username={}", credential.username);
                println!("password={}", credential.password);
            }
            Packet::Result { message, .. } => {
                eprintln!(
                    "Failed to fetch credential from the nicator store. You may need to `nicator unlock`. Received from daemon: {}",
                    message
                );
            }
            _ => {}
        }
        Ok(())
    }

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
