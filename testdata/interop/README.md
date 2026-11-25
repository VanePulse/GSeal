# Interop fixtures (fake data only)

Backup bundles written by VaneSecret (Node, commit `ca87d68`) with
`tools/geninterop/geninterop.sh` on a throwaway fake store. They contain only
the fake values below and a throwaway data key. GSeal must verify and restore
them (`test/interop_test.go`).

| File | Test passphrase as typed |
|---|---|
| `node-ascii.wsbk` | `interop test passphrase` |
| `node-precomposed.wsbk` | `café passphrase été`, each `é` typed precomposed (U+00E9) |
| `node-decomposed.wsbk` | the same, each `é` typed decomposed (`e` + U+0301) |

The passphrase is NFC-normalized before scrypt, so both input forms open both
`é` bundles; a passphrase whose NFC differs (`e` instead of `é`) must not.

Fake store content (`interop.ini`):

| Node | Key | Value |
|---|---|---|
| n1 | HOST | `interop.invalid` |
| n1 | PORT | `6379` |
| n1 | PSWD | `interop-secret-1234` (encrypted) |
| n1 | TOKEN | `tok ;with comment char` (encrypted) |
| n2 | USER | `alice` |
| n2 | PSWD | `密码-ünïcode-5678` (encrypted) |
