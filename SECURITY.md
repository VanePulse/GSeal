# Security

## What with-secrets is for

`with-secrets` lets an AI assistant or a script **use** a credential without
**seeing** it: the value is injected into one child process as an
environment variable, and everything that process prints is masked. Values
the encryption policy selects are encrypted at rest; see below for what that
covers.

## Threat model

### What it protects against

- **A copy of the store or of a backup, for the values stored encrypted.**
  Values the encryption policy selects are stored as AES-256-GCM ciphertext
  (`ENC:v1:`), bound to facility, section and key. The data key is wrapped by
  the key backend: with `systemd-creds --user` it can only be unwrapped on
  this machine by this user; with the `passphrase` backend only with the store
  passphrase. Backup bundles are encrypted as a whole (every file, plain values
  included, and the data key) with a key derived from the backup passphrase
  (scrypt, N=2^17, r=8, p=1).

  Values the policy leaves in plain text are **not** protected at rest: anyone
  who can read `<store>/env/*.ini` or the local copies in `<store>/env/.backup/`
  reads them. With the default policy (`@mask`) these are the keys on the
  plain list (`HOST`, `PORT`, `USER`, ...); an empty `[encrypt] keys` encrypts
  every value. Keep secrets out of plain keys, and check the store with
  `with-secrets --policy` and `with-secrets doctor`. Doc text (`@desc`) and
  comments are never encrypted.
- **Credentials pasted into chats, logs and terminals by accident.** Output of
  the child process (stdout and stderr) is streamed through a redactor that
  replaces every secret value, also URL-encoded and base64, with `***`. The
  audit log records names and exit codes, never values. `--list` and
  `doctor` never print values.
- **Half-finished changes.** Management commands hold a lock, write files
  atomically and journal multi-file changes, so a crash leaves either the old
  or the new state (see README, "Consistency").

### What it does not protect against

- **Other processes of the same user.** With the default backend any process
  running as you can unwrap the data key, read the child's environment
  (`/proc/<pid>/environ`) or call `with-secrets` itself. Use separate users
  (or machines) for separate trust levels.
- **A child process that misuses the credential.** The child gets the real
  value; it can use it for anything the credential allows, or send it
  somewhere in a transformed form (split, encrypted, ...) that the redactor
  cannot recognise. Masking is a safeguard against accidents, not a sandbox.
- **root, a compromised kernel, or physical access to an unlocked machine.**
- **Weak passphrases.** Backup and store passphrases must be at least 12
  characters; a guessable one weakens the bundles and the passphrase backend.

### Things to do

- Keep backups outside the machine (`with-secrets --backup <external dir>`) and
  check them with `--verify-backup`.
- Run `with-secrets doctor` after changes; it reports loose permissions,
  undecryptable values, missing or unverifiable backups and interrupted
  operations.
- Rotate a credential at its source if you suspect it was exposed; use
  `with-secrets --rotate-datakey` if the data key may have leaked.

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a
vulnerability" (Security tab of the repository), not in public issues. Do not
include real credentials in a report; use fake values (`*.invalid` hosts).
