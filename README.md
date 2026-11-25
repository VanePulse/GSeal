# GSeal

**Let AI assistants and scripts *use* credentials without *seeing* them.**

`with-secrets` runs a command with credentials from a local store injected as
environment variables, and masks their values in everything the command
prints. Secret values are encrypted at rest.

```sh
with-secrets redis.dev -- 'redis-cli -h "$REDIS_DEV_HOST" -p "$REDIS_DEV_PORT" ping'
```

Linux and macOS. MIT licensed. See [SECURITY.md](SECURITY.md) for what it
does and does not protect against.

## Install

From a release archive (`gseal-<version>-<os>-<arch>.tar.gz`, checked against
`SHA256SUMS`):

```sh
tar xzf gseal-0.1.0-linux-amd64.tar.gz && cd gseal-0.1.0-linux-amd64
./install.sh                          # /usr/local as root, else ~/.local
./install.sh --prefix ~/.local --store /srv/secrets
```

From source (Go 1.24 or newer, no network needed: dependencies are vendored):

```sh
./install.sh --prefix ~/.local        # builds with go, version from VERSION
```

`install.sh` keeps every version side by side and switches atomically:

```
<prefix>/lib/gseal/<version>/with-secrets
<prefix>/lib/gseal/current  -> <version>
<prefix>/bin/with-secrets   -> ../lib/gseal/current/with-secrets   (also bin/gseal)
```

| Option | |
|---|---|
| `--prefix DIR` | default `/usr/local` when writable, else `~/.local` |
| `--binary FILE` | install this executable instead of building |
| `--store DIR` | written as `[store] path` into a new config file |
| `--link-store-bin` | make `<store>/bin/with-secrets` a link to the new entry (old scripts keep working; `<store>/bin` is copied to `bin.bak-<time>` first) |
| `--check` | verify the installation (exit 1 if anything is wrong) |
| `--rollback` | switch back to the previous version |

The first install writes `~/.config/gseal/config.ini`; an existing config is
never changed (the differences from the template are shown).
`uninstall.sh [--prefix DIR]` removes the program and its links; it never
removes the store, the config or any backup, and puts a backed-up
`<store>/bin` back.

Quick start. The first command depends on the machine:

```sh
with-secrets --init                       # Linux with systemd 256 or newer (systemd-creds --user)
with-secrets --init --backend passphrase  # macOS, or Linux without it: a store passphrase protects the data key
```

then (with the `passphrase` backend each command that needs the data key asks
for the store passphrase on the terminal):

```sh
with-secrets --new redis dev              # template in <store>/env/_import/redis.ini
$EDITOR ~/.local/share/gseal/env/_import/redis.ini
with-secrets --import redis               # encrypt and store; the import file is shredded
with-secrets --backup /mnt/usb/gseal      # set a backup passphrase
with-secrets redis.dev -- 'redis-cli -h "$REDIS_DEV_HOST" ping'
with-secrets doctor
```

## How it works

- Credentials live in INI files, one per facility: `<store>/env/<facility>.ini`.
  Each `[section]` is a node; `<facility>.<section>` is its logical name.
- `with-secrets <facility>.<section> -- <command>` injects every key of that
  section as `<FACILITY>_<SECTION>_<KEY>` (upper case), e.g. `redis.dev` +
  `PSWD` → `REDIS_DEV_PSWD`. `[DEFAULT]` keys are inherited. Several logical
  names can be combined.
- A single argument after `--` is run by `bash -c`, so quote it with single
  quotes: variables then expand only inside the child, after injection.
- Output (stdout and stderr) is streamed through a redactor: every secret value
  (also URL-encoded and base64) becomes `***`. Values of non-secret keys
  (`HOST`, `PORT`, `USER`, ... — see `[redact] plain`) stay readable.
- Every call is appended to `<store>/logs/audit.log` (names, command with
  secrets masked, exit code; never values).

## Documenting credentials

Docs live in the INI files themselves, Javadoc style:

```ini
; @desc Redis cache
; Keys:
;   HOST  server address
;   PSWD  password (use REDISCLI_AUTH)

[dev]
; @desc Development instance
HOST = redis-dev.example.invalid
PSWD = ...
```

```sh
with-secrets --list              # files
with-secrets --list redis        # nodes of a file
with-secrets --list redis.dev    # variables of a node, with key meanings
```

Commented-out assignments (`; PSWD = old`) are never shown. Secrets pasted into
doc text are masked as whole tokens.

## Store location

The first of these that is set decides; if it does not point to a store, that
is an error (there is no fallback to the next one):

1. `--store <dir>` (before the other arguments)
2. `GSEAL_STORE`
3. `WITH_SECRETS_ROOT` (compatibility)
4. `[store] path` in the config file
5. `~/.local/share/gseal` (fixed; `XDG_DATA_HOME` is not consulted)

`with-secrets --where` shows the store in use and where it came from.

## Configuration

`$XDG_CONFIG_HOME/gseal/config.ini` (default `~/.config/gseal/config.ini`, or
`GSEAL_CONFIG`). Unknown sections or keys are errors.

```ini
[store]
path = /srv/secrets           ; store root (contains env/ and logs/)

[encrypt]
keys = @mask                  ; empty = encrypt every key
                              ; @mask = keys not on the plain list (default)
                              ; or names / patterns: PSWD, TOKEN, *_SECRET

[redact]
plain = HOST, PORT, DB, DATABASE, USER, USERNAME, NAME, SCHEMA, ENDPOINT, BUCKET, BUCKETNAME

[backup]
dir = /mnt/backup/gseal

[audit]
enabled = true
```

- A key is *plain* if it equals a word of `[redact] plain` or ends in
  `_<word>` (`SRC_HOST` counts as `HOST`). Plain values are shown in output.
- A value stored encrypted is **always** masked: also under a plain key, and
  also where it appears inside a longer plain value (an unencrypted secret
  inside a plain value is shown, as before).
- A file can override the encryption policy with a file-level
  `; @encrypt <spec>` line (same syntax as `keys`).
- `with-secrets --policy [<file>]` shows, per key, what the policy wants and how
  the value is stored now — without showing any value.

## Managing credentials

Management commands are run by you, in your own terminal. A backup passphrase
is only ever read from the terminal (no echo); it is never taken from
arguments or environment variables.

```sh
with-secrets --init                    # create the data key (first use)
with-secrets --new mail [alert]        # template env/_import/mail.ini with <fill>
with-secrets --export redis            # env/_import/redis.ini, secrets as <hold>
with-secrets --import redis            # validate, merge, encrypt, shred the import file
```

In an import file, `<hold>` keeps the stored value, `<delete>` removes the
key, `<fill>` must be replaced, anything else is the new value. Keys and
sections missing from the import file are kept. Key names are matched without
regard to case. Nothing is written unless the whole file validates; the import
file is overwritten with zeros and deleted afterwards. An import never decrypts
a stored ciphertext; new values are encrypted by the encryption policy.

### Single values, policy changes, key rotation

```sh
with-secrets --set redis.dev PSWD           # type the value (no echo); encrypted by the policy
with-secrets --set redis.dev TOKEN --create # also create a missing key / node / file
with-secrets --apply-policy --dry-run       # per file: how many values would be encrypted / decrypted
with-secrets --apply-policy                 # rewrite every file by the policy (never decrypts ...)
with-secrets --apply-policy --allow-decrypt # (... unless you allow it)
with-secrets --rotate-datakey               # new data key; every encrypted value re-encrypted
```

`--apply-policy` and `--rotate-datakey` replace all affected files (and the
data key) together through the same journal as a restore: a failure leaves the
store unchanged, an interruption is completed by the next management command.
Each change ends with one automatic backup.

### Checking the setup

```sh
with-secrets doctor
```

One `OK` / `WARN` / `FAIL` line per item: config, store path and permissions,
key backend, data key, whether every encrypted value decrypts, whether the
store matches the policy, backup key and directory, the latest backup (is it
restorable with the current passphrase?), interrupted operations, pending
import files, the audit log. It never prints a value and changes nothing.
Exit code 1 if anything is `FAIL`.

### Backups

```sh
with-secrets --backup /mnt/usb/gseal   # first time: set a passphrase (>= 12 characters)
with-secrets --backup [--new-password] # later: no prompt (stored key), or a new passphrase
with-secrets --verify-backup <bundle>  # passphrase right, every value decrypts
with-secrets --restore <bundle>        # new machine / disaster; re-binds the data key
with-secrets --undo-restore            # put back the store the last restore moved aside
```

- A bundle (`secrets-<kind>-<time>.wsbk`) holds every file and the data key,
  encrypted with AES-256-GCM under `scrypt(NFC(passphrase))`. The format is the
  same as VaneSecret's, in both directions.
- Every `--import` makes an automatic backup. The first bundle in a directory
  is the permanent *base*; the newest 19 *auto* bundles are kept; *manual*
  bundles are never deleted. Damaged bundles and bundles made with another
  passphrase are reported and never counted or deleted.
- Backup directory: `--backup <dir>` (remembered for automatic backups) >
  the remembered directory > `[backup] dir` > `$TMPDIR/with-secrets-backup`
  (a temporary directory is wiped on reboot: a warning tells you so).

### Consistency

Management commands hold an exclusive lock (`flock` on `<store>/env/.lock`),
publish files atomically (temp file, fsync, rename), and replace the store on
restore in two journaled phases, so an interruption at any point is either
rolled back or completed by the next management command.

| Exit code | Meaning |
|---|---|
| 0 | done |
| 1 | failed; the store is unchanged |
| 3 | the store changed (committed), but a follow-up step (shredding, automatic backup, saving a setting) did not complete; the message says what to run |
| 5 | a restore / undo was interrupted; the next management command completes it |

## Key backends

The data key (and the backup key) are wrapped by a key backend, chosen with
`--init --backend <name>` (or `--restore <bundle> --backend <name>`); the
store remembers it through the credential files themselves.

| Backend | Binding | Prompts |
|---|---|---|
| `systemd-creds` (default) | `systemd-creds --user`: this machine and this user (systemd 256 or newer) | none |
| `passphrase` | a store passphrase (scrypt, AES-256-GCM); for machines without systemd-creds | the store passphrase, on the terminal, once per command that needs the data key |

## Encryption at rest

Secret values are stored as `ENC:v1:<base64url(nonce | ciphertext | tag)>`,
AES-256-GCM with the facility, section and key as associated data (a
ciphertext moved to another key does not decrypt). The 32-byte data key is
wrapped with `systemd-creds --user` (bound to this machine and user) in
`<store>/env/.datakey.cred`.

## Building and testing

Go 1.24 or newer, no network needed:

```sh
CGO_ENABLED=0 go build -mod=vendor -trimpath -o with-secrets ./cmd/with-secrets
go test ./...                                   # needs systemd-creds --user for some suites
GSEAL_TEST_BACKEND=testfile go test ./test/     # anywhere (test-only key backend)
tools/release.sh dist                           # release archives + SHA256SUMS
```

Tests run against fake stores only. See [test/BASELINE.md](test/BASELINE.md)
for how the tests map to the behaviour of the previous implementation, and
[CHANGELOG.md](CHANGELOG.md) for what changed.

## License

MIT
