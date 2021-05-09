use std::{io::{Read, Write}, process::{Command, ExitStatus, Stdio}};

const BINARY_PATH: &str = env!("CARGO_BIN_EXE_nicator");
const SOCKET_PATH: &str = "./cli-nicator.sock";
const STORE_PATH: &str = "./.cli-credentials";
const PASSPHRASE: &[u8] = b"abc123\n";
const WRITE_CRED: &[u8] = b"host=test.com\nprotocol=http\nusername=user\npassword=pw\n";
const READ_CRED: &[u8] = b"host=test.com\nprotocol=http";

#[test]
fn cli() {
    let (init_result, _) = spawn_nicator(&["init"], PASSPHRASE);
    let (unlock_result, _) = spawn_nicator(&["unlock"], PASSPHRASE);
    let (store_result, _) = spawn_nicator(&["store"], WRITE_CRED);
    let (get_result, get_output) = spawn_nicator(&["get"], READ_CRED);
    let (erase_result, _) = spawn_nicator(&["erase"], READ_CRED);
    let (lock_result, _) = spawn_nicator(&["lock"], PASSPHRASE);
    std::fs::remove_file(STORE_PATH).ok();
    assert!(init_result.success());
    assert!(unlock_result.success());
    assert!(store_result.success());
    assert!(get_result.success());
    assert!(get_output.contains("username=user"));
    assert!(get_output.contains("password=pw"));
    assert!(erase_result.success());
    assert!(lock_result.success());
}

fn spawn_nicator(args: &[&str], input: &[u8]) -> (ExitStatus, String) {
    let mut base_flags = vec!["-c", STORE_PATH, "-s", SOCKET_PATH];
    base_flags.extend_from_slice(args);
    let mut handle = Command::new(BINARY_PATH)
        .args(base_flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to launch nicator process.");
    let mut stdin = handle.stdin.take().unwrap();
    stdin
        .write_all(input)
        .expect("Failed to write to nicator stdin.");
    drop(stdin);
    let mut stdout = handle.stdout.take().unwrap();
    let mut output = Vec::<u8>::new();
    stdout.read_to_end(&mut output).expect("Failed to read nicator output.");
    let output = String::from_utf8(output).expect("Output is invalid utf8.");
    (handle.wait().expect("Failed to await nicator process."), output)
}
