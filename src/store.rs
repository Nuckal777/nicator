use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use byteorder::ReadBytesExt;
use chacha20poly1305::{
    aead::{AeadMut, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{OsRng, RngCore};
use serde_derive::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;

const SALT_LEN: usize = 22;
const NONCE_LEN: usize = 12;
const FILE_VERSION: u8 = 1;

#[derive(Clone, Deserialize, Serialize)]
pub struct Credential {
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub username: String,
    pub password: String,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            protocol: String::new(),
            host: String::new(),
            password: String::new(),
            path: String::new(),
            username: String::new(),
        }
    }
}

impl Credential {
    pub fn from_git(git_credential: &str) -> Credential {
        let mut credential = Credential::default();
        for line in git_credential.lines() {
            let splitted: Vec<&str> = line.split('=').collect();
            let key = splitted[0];
            let value_parts: Vec<&str> = splitted.iter().skip(1).copied().collect();
            let value = value_parts.concat();
            match key {
                "protocol" => credential.protocol = value,
                "host" => credential.host = value,
                "password" => credential.password = value,
                "path" => credential.path = value,
                "username" => credential.username = value,
                _ => {}
            }
        }
        credential
    }
}

#[derive(Deserialize, Serialize)]
pub struct Store {
    pub credentials: Vec<Credential>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }
}

impl Store {
    pub fn decrypt<R: std::io::Read>(
        reader: &mut R,
        passphrase: &str,
    ) -> Result<Store, crate::Error> {
        let mut salt_data = [0_u8; SALT_LEN];
        let mut nonce_data = [0_u8; NONCE_LEN];
        let mut store_data = Vec::<u8>::new();
        // file version we currently do not care about
        let _version = reader.read_u8()?;
        reader.read_exact(&mut salt_data)?;
        reader.read_exact(&mut nonce_data)?;
        reader.read_to_end(&mut store_data)?;

        // Argon2 with default params (Argon2id v19)
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password_simple(
                passphrase.as_bytes(),
                std::str::from_utf8(&salt_data).map_err(|_| crate::Error::Crypto)?,
            )
            .map_err(|_| crate::Error::Crypto)?
            .hash
            .ok_or(crate::Error::Crypto)?;

        let key = Key::from_slice(password_hash.as_bytes());
        let mut cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&nonce_data);
        let plain = cipher
            .decrypt(&nonce, store_data.as_slice())
            .map_err(|_| crate::Error::Crypto)?;
        let store = bincode::deserialize(&plain)?;
        Ok(store)
    }

    pub fn decrypt_from<P: AsRef<std::path::Path>>(
        path: P,
        passphrase: &str,
    ) -> Result<Store, crate::Error> {
        let mut reader = std::fs::File::open(path)?;
        Self::decrypt(&mut reader, passphrase)
    }

    pub fn encrypt<W: std::io::Write>(
        &self,
        writer: &mut W,
        passphrase: &str,
    ) -> Result<(), crate::Error> {
        let salt = SaltString::generate(&mut OsRng);
        // Argon2 with default params (Argon2id v19)
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password_simple(passphrase.as_bytes(), salt.as_ref())
            .map_err(|_| crate::Error::Crypto)?
            .hash
            .ok_or(crate::Error::Crypto)?;

        let mut nonce_data = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_data);

        let data = bincode::serialize(&self)?;
        let key = Key::from_slice(password_hash.as_bytes());
        let mut cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&nonce_data);
        let encrypted = cipher
            .encrypt(nonce, data.as_slice())
            .map_err(|_| crate::Error::Crypto)?;

        writer.write_all(&[FILE_VERSION])?;
        writer.write_all(salt.as_bytes())?;
        writer.write_all(nonce.as_slice())?;
        writer.write_all(&encrypted)?;
        Ok(())
    }

    pub fn encrypt_at<P: AsRef<std::path::Path>>(
        &self,
        path: P,
        passphrase: &str,
    ) -> Result<(), crate::Error> {
        let mut writer = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        self.encrypt(&mut writer, passphrase)?;
        Ok(())
    }

    /// Finds a credential in the store matching the desribed repo.
    /// Equality for protocol, host and path is checked firstly.
    /// Afterwards protocol and host equality matters.
    pub fn find(&self, protocol: &str, host: &str, path: &str) -> Option<Credential> {
        let result = self
            .credentials
            .iter()
            .find(|cred| cred.protocol == protocol && cred.host == host && cred.path == path);
        result.cloned().or_else(|| {
            self.credentials
                .iter()
                .find(|cred| cred.protocol == protocol && cred.host == host && cred.path.is_empty())
                .cloned()
        })
    }

    pub fn erase(&mut self, protocol: &str, host: &str, path: &str) {
        self.credentials
            .retain(|cred| !(cred.protocol == protocol && cred.host == host && cred.path == path));
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    fn setup_store() -> super::Store {
        super::Store {
            credentials: vec![
                super::Credential {
                    host: "host1".to_string(),
                    password: "pw1".to_string(),
                    path: "path1".to_string(),
                    protocol: "protocol1".to_string(),
                    username: "user1".to_string(),
                },
                super::Credential {
                    host: "host2".to_string(),
                    password: "pw2".to_string(),
                    path: "path2".to_string(),
                    protocol: "protocol2".to_string(),
                    username: "user2".to_string(),
                },
            ],
        }
    }

    #[test]
    fn store_decrypt() {
        let store = setup_store();
        let mut encrpyted = Vec::<u8>::new();
        store
            .encrypt(&mut Cursor::new(&mut encrpyted), "pw123")
            .unwrap();
        let result = super::Store::decrypt(&mut Cursor::new(&encrpyted), "pw123").unwrap();
        let failed = super::Store::decrypt(&mut Cursor::new(&encrpyted), "pw234");
        assert_eq!(result.credentials.len(), 2);
        assert!(failed.is_err());
    }

    #[test]
    fn erase() {
        let mut store = setup_store();
        store.erase("protocol1", "host1", "path1");
        assert_eq!(store.credentials.len(), 1);
    }
}
