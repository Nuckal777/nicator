use std::{
    io::{Read, Write},
    process::{Command, ExitStatus, Stdio},
};

const BINARY_PATH: &str = env!("CARGO_BIN_EXE_nicator");
const SOCKET_PATH: &str = "./cli-nicator.sock";
const STORE_PATH: &str = "./.cli-credentials";
const GIT_PATH: &str = "./.git-credentials";
const PASSPHRASE: &str = "abc123";
const GIT_CRED: &[u8] = b"\nhttps://gituser:gitpw@git.com/repo";
const WRITE_CRED: &[u8] = b"host=test.com\nprotocol=http\nusername=user\npassword=pw\n";
const READ_CRED: &[u8] = b"host=test.com\nprotocol=http";

#[test]
fn cli() {
    std::fs::write(GIT_PATH, GIT_CRED).expect("Failed to create mock .git_credentials");
    let (init_result, _) = spawn_nicator(&["-p", PASSPHRASE, "init"], &[]);
    let (import_result, _) = spawn_nicator(&["-p", PASSPHRASE, "import", "-g", GIT_PATH], &[]);
    let (unlock_result, _) = spawn_nicator(&["-p", PASSPHRASE, "unlock"], &[]);
    let (store_result, _) = spawn_nicator(&["store"], WRITE_CRED);
    let (get_result, get_output) = spawn_nicator(&["get"], READ_CRED);
    let (export_result, export_output) = spawn_nicator(&["-p", PASSPHRASE, "export"], &[]);
    let (erase_result, _) = spawn_nicator(&["erase"], READ_CRED);
    let (lock_result, _) = spawn_nicator(&["lock"], &[]);
    std::fs::remove_file(GIT_PATH).ok();
    std::fs::remove_file(STORE_PATH).ok();
    assert!(init_result.success());
    assert!(import_result.success());
    assert!(unlock_result.success());
    assert!(store_result.success());
    assert!(get_result.success());
    assert!(get_output.contains("username=user"));
    assert!(get_output.contains("password=pw"));
    assert!(export_result.success());
    assert!(export_output.contains("username=user"));
    assert!(export_output.contains("password=pw"));
    assert!(export_output.contains("protocol=http"));
    assert!(export_output.contains("host=test.com"));
    assert!(export_output.contains("path="));
    assert!(export_output.contains("username=gituser"));
    assert!(export_output.contains("password=gitpw"));
    assert!(export_output.contains("protocol=https"));
    assert!(export_output.contains("host=git.com"));
    assert!(export_output.contains("path=repo"));
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
    stdout
        .read_to_end(&mut output)
        .expect("Failed to read nicator output.");
    let output = String::from_utf8(output).expect("Output is invalid utf8.");
    (
        handle.wait().expect("Failed to await nicator process."),
        output,
    )
}
