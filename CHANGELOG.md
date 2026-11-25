# Changelog

All notable changes are listed here. Versions follow semantic versioning.

## 0.1.0 (2026-11-25)

First release of GSeal, a Go rewrite of the Node.js `with-secrets` tool.
Stores and backup bundles of the previous implementation are used as they
are, in both directions.

Produced under the supervision of VanePulse throughout, implemented by
Claude (Anthropic), and reviewed automatically by ReviewCli, a VanePulse
product.

### Kept from the previous implementation

- Injection of `<FACILITY>_<NODE>_<KEY>` variables, streaming output
  redaction (also URL-encoded and base64 forms), `@desc` docs and `--list`,
  audit log.
- `--init`, `--new`, `--export`, `--import`, `--backup`, `--verify-backup`,
  `--restore`, `--undo-restore`, automatic backups with rotation, the
  management lock, journaled restore and crash recovery; exit codes 0/1/3/5.

### New

- A single static executable; no runtime to install.
- Configuration file (`config.ini`): store path, encryption policy, plain-key
  list, backup directory, audit switch. Store location: `--store`,
  `GSEAL_STORE`, `WITH_SECRETS_ROOT`, the config, `~/.local/share/gseal`.
- Encryption policy (`[encrypt] keys`, file-level `@encrypt`) separate from
  output masking; encrypted values are always masked.
- `--policy`, `--apply-policy [--dry-run] [--allow-decrypt]`, `--set`,
  `--rotate-datakey`, `doctor`, `--where`, `--version`.
- Key backends: `systemd-creds` (default) and `passphrase`.
- Backup passphrases are NFC-normalized (precomposed and decomposed input open
  the same bundle).
- `install.sh` / `uninstall.sh` with side-by-side versions, atomic switching,
  `--check`, `--rollback` and `--link-store-bin`.
- English messages.
