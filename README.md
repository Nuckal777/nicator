# Nicator

![Build Status](https://img.shields.io/github/actions/workflow/status/Nuckal777/nicator/test.yaml?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/Nuckal777/nicator/badge.svg?branch=master)](https://coveralls.io/github/Nuckal777/nicator?branch=master)

A lightweight encrypting git credential helper (for Linux)

## Motivation
Git on linux has basically 3 options to store credentials.
- [git-credential-cache](https://git-scm.com/docs/gitcredentials): stores credentials in-memory, which means that they are not saved across reboots.
- [git-credential-store](https://git-scm.com/docs/gitcredentials): stores credentials unencrypted on a filesystem, so anybody with access to the file can read them.
- libsecret based implementations (like this [one](https://github.com/shugo/git-credential-gnomekeyring)): These store credentials encrypted, but bring a full secret management solution and require workarounds without a graphical session ([see here](https://superuser.com/questions/141036/use-of-gnome-keyring-daemon-without-x)).

With GitHub's move to personal access tokens, I felt the need for a lightweight encrypting solution.
Nicator works like git-credential-store but it encrypts the saved credentials, so it protects against the credentials file getting stolen.
__It does not do anything about malicious code being executed or its sockets and process memory getting read, especially after unlocking.__
Most of nicators dependencies are statically linked, so it does not require any uncommon dependencies.

## Usage
1. Add `nicator` somewhere on your `$PATH`.
2. Execute `nicator init` to create the credentials file and set an initial password.
3. Set `nicator` as your git-credential-helper: `git config --global credential.helper /path/to/nicator`.
4. Execute `nicator unlock` to enable storing and fetching credentials.
5. Execute `nicator lock` to disable storing and fetching credentials.

`nicator unlock -t SECONDS` allows specifying a timeout after which the credentials become inaccessible.
It defaults to 1 hour. It might be handy to create a shell alias to change it consistently. The `-c` and `-s` flags can be used to change the path used for the credentials file and socket file respectively.
These should not leak any data as long these files are only readable and writeable by the the file's owner, which nicator takes care of when creating these.

An existing `.git-credentials` file can be imported using `nicator import`.

## How nicator works
Unlocking will automatically launch a nicator server/daemon process listening on a unix socket with appropriate permissions (found in `/tmp`), which keeps the password in-memory.
When queried for data the server will decrypt the credential file (`$HOME/.nicator-credentials`) or encrypt it with appropriate permissions when storing.
`nicator store/get/erase` will parse git's input, connect to the daemon and output required information to be consumed by git.
Nicator encrypts credentials using 256-bit AES.
The passphrase is hashed using Argon2id.

## Security considerations
To put it bluntly after unlocking `nicator` is as insecure as `git-credential-store`.
- You should trust the root user on your system.
- When hibernating your nicator password may be written to the disk if a nicator server is still running
- Malicious code may act like a valid the nicator client and read credentials from the unix socket after the credential store is unlocked
