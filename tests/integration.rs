use std::{error::Error, path::PathBuf, str::FromStr};

use nicator::client::Client;

const SOCKET_PATH: &str = "./nicator.sock";
const STORE_PATH: &str = "./.nicator-credentials";
const PASSPHRASE: &str = "pw123";

#[test]
fn integration() -> Result<(), Box<dyn Error>> {
    let store = nicator::store::Store::default();
    store
        .encrypt_at(PathBuf::from_str(STORE_PATH)?, PASSPHRASE)
        .expect("Failed to create .nicator-credentials file.");
    run_integration();
    std::fs::remove_file(STORE_PATH)?;
    Ok(())
}

fn run_integration() {
    let server_thread = std::thread::spawn(|| {
        nicator::server::launch(SOCKET_PATH).expect("Failed to launch nicator server");
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    create_client()
        .unlock(
            PASSPHRASE.to_string(),
            PathBuf::from_str(STORE_PATH).unwrap(),
            20,
        )
        .expect("Failed to unlock.");
    create_client()
        .store(nicator::store::Credential {
            host: "host1".to_string(),
            password: "pw1".to_string(),
            path: "path1".to_string(),
            protocol: "protocol1".to_string(),
            username: "user1".to_string(),
        })
        .expect("Failed to store credential.");
    let opt_cred = create_client()
        .get(nicator::store::Credential {
            host: "host1".to_string(),
            password: String::new(),
            path: "path1".to_string(),
            protocol: "protocol1".to_string(),
            username: String::new(),
        })
        .expect("Failed to fetch credential");
    create_client().lock().expect("Failed to lock.");
    server_thread.join().expect("Failed to join server thread.");
    let cred = opt_cred.expect("Cannot find added added credential.");
    assert_eq!(cred.username, "user1");
    assert_eq!(cred.password, "pw1");
}

fn create_client() -> Client {
    nicator::client::Client::new(SOCKET_PATH).expect("Failed to create client.")
}
