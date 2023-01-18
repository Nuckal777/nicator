use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use byteorder::ReadBytesExt;
use chacha20poly1305::KeyInit;
use chacha20poly1305::{aead::AeadMut, ChaCha20Poly1305, Key, Nonce};
use percent_encoding::percent_decode_str;
use rand_core::{OsRng, RngCore};
use secstr::SecUtf8;
use serde_derive::{Deserialize, Serialize};
use std::{os::unix::fs::OpenOptionsExt, slice::Iter};

const SALT_LEN: usize = 22;
const NONCE_LEN: usize = 12;
const FILE_VERSION: u8 = 1;

#[derive(Clone, Deserialize, Serialize)]
pub struct Credential {
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub username: String,
    pub password: SecUtf8,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            protocol: String::new(),
            host: String::new(),
            password: SecUtf8::from(""),
            path: String::new(),
            username: String::new(),
        }
    }
}

impl Credential {
    #[must_use]
    pub fn from_git(git_credential: &str) -> Credential {
        let mut credential = Credential::default();
        for line in git_credential.lines() {
            let splitted: Vec<&str> = line.split('=').collect();
            let key = splitted[0];
            let value_parts: Vec<&str> = splitted.iter().skip(1).copied().collect();
            let value = value_parts.join("=");
            match key {
                "protocol" => credential.protocol = value,
                "host" => credential.host = value,
                "password" => credential.password = SecUtf8::from(value),
                "path" => credential.path = value,
                "username" => credential.username = value,
                _ => {}
            }
        }
        credential
    }

    /// Creates a credential from the given url.
    /// # Errors
    /// If the url is not valid.
    pub fn from_url(url_str: &str) -> Result<Credential, url::ParseError> {
        let url = url::Url::parse(url_str)?;
        let port = url.port().map_or(String::new(), |p| format!(":{p}"));
        Ok(Credential {
            host: url.host_str().unwrap_or("").to_string() + &port,
            // leading slash is not required for git
            path: url.path()[1..].to_string(),
            protocol: url.scheme().to_string(),
            // decode percent encoding
            password: SecUtf8::from(
                percent_decode_str(url.password().unwrap_or(""))
                    .decode_utf8()
                    .expect("failed to decode percent encoded password.")
                    .to_string(),
            ),
            username: percent_decode_str(url.username())
                .decode_utf8()
                .expect("failed to decode percent encoded username.")
                .to_string(),
        })
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct Store {
    credentials: Vec<Credential>,
}

impl Store {
    /// Decrypts a store instance from the given reader.
    /// # Errors
    /// Can fail due to I/O or cryptography related errors.
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
            .hash_password(
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
            .decrypt(nonce, store_data.as_slice())
            .map_err(|_| crate::Error::Crypto)?;
        let store = bincode::deserialize(&plain)?;
        Ok(store)
    }

    /// Decrypts a store instance from the given path.
    /// # Errors
    /// Can fail due to I/O or cryptography related errors.
    pub fn decrypt_from<P: AsRef<std::path::Path>>(
        path: P,
        passphrase: &str,
    ) -> Result<Store, crate::Error> {
        let mut reader = std::fs::File::open(path)?;
        Self::decrypt(&mut reader, passphrase)
    }

    /// Encrypts a store instance to the given writer.
    /// # Errors
    /// Can fail due to I/O or cryptography related errors.
    pub fn encrypt<W: std::io::Write>(
        &self,
        writer: &mut W,
        passphrase: &str,
    ) -> Result<(), crate::Error> {
        let salt = SaltString::generate(&mut OsRng);
        // Argon2 with default params (Argon2id v19)
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(passphrase.as_bytes(), salt.as_ref())
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

    /// Encrypts a store instance at the given path.
    /// # Errors
    /// Can fail due to I/O or cryptography related errors.
    pub fn encrypt_at<P: AsRef<std::path::Path>>(
        &self,
        path: P,
        passphrase: &str,
    ) -> Result<(), crate::Error> {
        let mut writer = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        self.encrypt(&mut writer, passphrase)?;
        Ok(())
    }

    /// Updates a credential.
    /// If the credential does not already exist for the given protocol, host, path combination it will be added.
    pub fn update(&mut self, new_cred: Credential) {
        let result = self.credentials.iter_mut().find(|cred| {
            cred.protocol == new_cred.protocol
                && cred.host == new_cred.host
                && cred.path == new_cred.path
        });
        match result {
            Some(cred) => {
                cred.username = new_cred.username;
                cred.password = new_cred.password;
            }
            None => {
                self.credentials.push(new_cred);
            }
        }
    }

    /// Finds a credential in the store matching the desribed repo.
    /// Equality for protocol, host and path is checked firstly.
    /// Afterwards protocol and host equality matters.
    #[must_use]
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

    /// Deletes all credentials with matching protocol, host and path from the store.
    pub fn erase(&mut self, protocol: &str, host: &str, path: &str) {
        self.credentials
            .retain(|cred| !(cred.protocol == protocol && cred.host == host && cred.path == path));
    }

    /// Returns an iterator over all stored credentials.
    pub fn iter(&self) -> Iter<Credential> {
        self.credentials.iter()
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io::Cursor};

    use secstr::SecUtf8;

    fn setup_store() -> super::Store {
        super::Store {
            credentials: vec![
                super::Credential {
                    host: "host1".to_string(),
                    password: SecUtf8::from("pw1"),
                    path: "path1".to_string(),
                    protocol: "protocol1".to_string(),
                    username: "user1".to_string(),
                },
                super::Credential {
                    host: "host2".to_string(),
                    password: SecUtf8::from("pw2"),
                    path: String::new(),
                    protocol: "protocol2".to_string(),
                    username: "user2".to_string(),
                },
            ],
        }
    }

    #[test]
    fn credential_from_git() {
        let git_str = "username=abc\npassword=e=r\nhost=github.com\nprotocol=https\npath=dfg";
        let credential = super::Credential::from_git(git_str);
        assert_eq!(credential.host, "github.com");
        assert_eq!(credential.password.unsecure(), "e=r");
        assert_eq!(credential.path, "dfg");
        assert_eq!(credential.protocol, "https");
        assert_eq!(credential.username, "abc");
    }

    #[test]
    fn credential_from_url() -> Result<(), Box<dyn Error>> {
        let url_str = "https://abc:e=r@github.com/dfg";
        let credential = super::Credential::from_url(url_str)?;
        assert_eq!(credential.host, "github.com");
        assert_eq!(credential.password.unsecure(), "e=r");
        assert_eq!(credential.path, "dfg");
        assert_eq!(credential.protocol, "https");
        assert_eq!(credential.username, "abc");
        Ok(())
    }

    #[test]
    fn encrypt_decrypt() {
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
        store.erase("bla", "blup", "blop");
        assert_eq!(store.credentials.len(), 1);
    }

    #[test]
    fn update() {
        let mut store = setup_store();
        store.update(super::Credential {
            host: "host1".to_string(),
            password: SecUtf8::from("topsecret"),
            path: "path1".to_string(),
            protocol: "protocol1".to_string(),
            username: "user1".to_string(),
        });
        store.update(super::Credential {
            host: "host3".to_string(),
            password: SecUtf8::from("pw3"),
            path: "path3".to_string(),
            protocol: "protocol3".to_string(),
            username: "user3".to_string(),
        });
        assert_eq!(store.credentials.len(), 3);
        assert_eq!(store.credentials[0].password.unsecure(), "topsecret");
    }

    #[test]
    fn find() {
        let store = setup_store();
        let found = store.find("protocol1", "host1", "path1");
        let not_found = store.find("protocol1", "host1", "another_path");
        assert!(found.is_some());
        assert!(not_found.is_none());
    }

    #[test]
    fn find_no_path() {
        let store = setup_store();
        let found = store.find("protocol2", "host2", "");
        let not_found = store.find("protocol1", "host1", "");
        assert!(found.is_some());
        assert!(not_found.is_none());
    }

    #[test]
    fn iter() {
        let store = setup_store();
        let iter = store.iter();
        assert_eq!(iter.count(), 2);
    }
}
