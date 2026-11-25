# Test baseline

GSeal is a rewrite of VaneSecret (Node.js, commit `ca87d68`). Its behaviour is
pinned by VaneSecret's black-box tests, ported here as Go tests that run the
built `with-secrets` executable against fake stores. Each ported check is
named after the baseline assertion it ports: `m1_L090` = `test/m1.mjs` line 90.

## Classes

| Class | Meaning |
|---|---|
| **K** keep | Same condition; only the way the program is called changes. |
| **E** English | The assertion matched Chinese tool output. It now matches the message by ID (`msg.Pattern(id)`), never by literal English; the meaning (refused, warned, which names are reported, exit code) is unchanged. Fixture text such as `@desc` docs stays as written. |
| **R** replace | Conflicts with a new requirement; replaced by the case below. |

## Replacements

| ID | Replaces | Replacement (stage) |
|---|---|---|
| R1 | m1:235, m1:239 (shim locates the Node code; works via a symlink) | M1 `TestM1R1Entry`: the executable is called directly and through two levels of symlinks; `WITH_SECRETS_*` / `GSEAL_*` never reach the child. M4 repeats this on the layout made by `install.sh`. |
| R2 | m1:242 (shim exits 127 when the code is missing) | M4: a `current` link to a missing version makes `install.sh --check` fail; calling the entry gives 127 from the shell. |
| R3 | m1:244 (fails when `WITH_SECRETS_ROOT` is unset) | M1 `TestM1R3StoreResolution`: `--store` > `GSEAL_STORE` > `WITH_SECRETS_ROOT` > config > default; `--where` names the source; a set source that is wrong is an error (no fallback); a missing default store is an error except for `--init`, and nothing is created. |
| R5 | relocate.mjs (all) | M4 install tests: install, upgrade (new version dir + atomic switch), `--rollback`, `--check`, `--link-store-bin`, failure injection with restore, uninstall keeps store, config and backups. |

The default backup directory is **unchanged** (`$TMPDIR/with-secrets-backup`
with a warning); `[backup] dir` is a new, optional setting.

## Platforms, key backends, builds

| Suite | Linux, systemd ≥ 256 (acceptance) | Linux CI | macOS CI |
|---|---|---|---|
| m1 port and M1 additions | ✔ | ✔ | ✔ |
| e2e port, backend systemd-creds | ✔ required | skipped (runner systemd 255 lacks `--user`) | ✘ |
| e2e port, backend testfile (`gsealtest` builds only) | ✔ | ✔ | ✔ |
| systemd-creds backend checks (platform `L-sd`) | ✔ required | skipped | ✘ |
| passphrase backend (M3) | ✔ | ✔ | ✔ |
| Interop: VaneSecret bundles → Go (golden files) | ✔ | ✔ | ✔ |
| Interop: Go → VaneSecret (needs `GSEAL_INTEROP_NODE_SRC` and node) | ✔ required | skipped | ✘ |
| install.sh (M4) | ✔ | ✔ | ✔ |

Fault injection points exist only in builds with the `gsealtest` tag; a
release build ignores `GSEAL_FAULT` / `GSEAL_CRASH`.

## Running

```sh
go test ./...                                    # unit tests and all suites (default backend systemd-creds)
GSEAL_TEST_BACKEND=testfile go test ./test/      # e2e with the test-only file backend (no systemd needed)
GSEAL_INTEROP_NODE_SRC=/path/to/VaneSecret/src GSEAL_REQUIRE_NODE=1 \
  go test ./internal/norm ./test/ -run 'Node|Interop'   # Go <-> VaneSecret, NFC against Node
GSEAL_TEST_KEEP=1 go test ./test/                # keep the scratch stores
```

The test suite builds two executables: the release build (what is shipped)
and a `-tags gsealtest` build with the fault-injection points
(`GSEAL_FAULT`, `GSEAL_CRASH`, `GSEAL_HOLD_MS`) and the `testfile` key backend.
The e2e port runs on the `gsealtest` build; `M2.F*` checks that the release
build contains neither.

## M2 additions (not in the baseline)

| ID | Check |
|---|---|
| `internal/norm` TestVectors | NFC equals Python `unicodedata` (Unicode 16.0) on every assigned code point, every composition pair and 10 000 random mark sequences (`testdata/norm/vectors.txt`, generated with the tables by `tools/gennorm/gennorm.py`) |
| `internal/norm` TestAgainstNode | NFC equals Node's `normalize('NFC')` on every code point assigned in Unicode 16.0 |
| I.1a–e | VaneSecret bundles (`testdata/interop`, ASCII / é precomposed / é decomposed) verify and restore in Go with either input form |
| I.2a–d | Go bundles (é typed precomposed / decomposed) verify and restore in VaneSecret with either input form |
| I.3 | a passphrase whose NFC differs (`e` for `é`) does not open |
| I.4a–c | a store written by VaneSecret: Go injects it, exports and re-imports it byte-identically, VaneSecret still reads it |
| M2.F1–F3 | the release build contains no fault-injection points or testfile backend and ignores `GSEAL_FAULT` / `GSEAL_CRASH` / `GSEAL_HOLD_MS` |
| M2.B1–B4 | backup directory order: `--backup <dir>` > remembered > `[backup] dir` > `$TMPDIR/with-secrets-backup` |
| M2.P1–P4 | import / export follow `[encrypt] keys` and file-level `@encrypt`; an import never decrypts a stored ciphertext |

## M3 (new features)

`go test -tags gsealtest ./test/ -run 'M3_'` (the M3 tests build both executables themselves).

| ID | Check |
|---|---|
| M3.A1–A8 | `--apply-policy`: dry run lists per file and changes nothing; widening encrypts everything with one backup; narrowing lists but does not decrypt without `--allow-decrypt`; with it, decrypts; failures at staging / swap roll back, a crash is completed by the next command; no value in the output |
| M3.S1–S9, T1 | `--set`: value from the terminal only, stored by the policy, one backup; missing file / node / key refused before any prompt unless `--create`; empty value refused; case-insensitive key; failure before the commit keeps the old value; typed after the prompt it is not echoed; the prompt line ends with CR LF |
| M3.R1–R5 | `--rotate-datakey`: failures at staging / wrap / swap leave store and key unchanged; afterwards every value opens with the new key and none with the old one (checked outside the program); one backup holding the new key; a crash is completed by the next command |
| M3.D1–D6 | `doctor`: OK/WARN/FAIL lines, no values; loose modes, pending import files and policy differences are WARN; damaged ciphertext, interrupted operations and config errors are FAIL (exit 1); doctor completes nothing |
| M3.V1–V5 | review M3-001: values that need quoting are stored and injected exactly (`--set`, `--apply-policy --allow-decrypt`); a value no INI form holds unchanged (U+2028 / U+2029 that would need quotes, both quote characters with edge spaces, line breaks) is refused before the commit, the store is unchanged; stored encrypted it is fine |
| M3.D7–D9 | review M3-002: a facility file that cannot be read (broken link, mode 000) is FAIL with its name and reason, exit 1; permissions, values and policy are then not reported as passed; doctor changes nothing |
| M3.E1–E6 | review M3-002/003: a store directory that cannot be listed is an error, never an empty store: dry run, apply, rotation and backup refuse (exit 1), doctor FAILs without reporting anything as passed; afterwards files and data key are unchanged and every value injects |
| M3.C1–C2 | review M3-004: doctor reports config errors by file, line, known field name and kind only; no text from the config (invalid values, unknown names, bad lines) appears in its output |
| M3.C3–C6 | review M3-004 (round 3): an invalid `[encrypt] keys`, an invalid file-level `@encrypt` and an invalid store version file are FAIL naming the config field / file only, never their text |
| M3.P0–P7 | passphrase backend on the release build with no systemd-creds on the PATH: init, import, injection (wrong passphrase refused), backup, restore with a new store passphrase, doctor |

## Assertions

Platform: `L/M` = Linux and macOS; `L-sd` = Linux with systemd-creds only.
Build: `test` = needs fault injection (`gsealtest` builds).

| Baseline (ca87d68) | Assertion | Class | Platform | Build | Stage | Note |
|---|---|---|---|---|---|---|
| m1.mjs:90 | injects prefixed names, incl. [DEFAULT] keys | K | L/M | - | M1 |  |
| m1.mjs:92 | no bare key names injected | K | L/M | - | M1 |  |
| m1.mjs:93 | WITH_SECRETS_* not passed to child | K | L/M | - | M1 |  |
| m1.mjs:97 | extra WITH_SECRETS_* from the parent are filtered from the child env | K | L/M | - | M1 |  |
| m1.mjs:100 | injection may not produce WITH_SECRETS_* names | K | L/M | - | M1 |  |
| m1.mjs:102 | several logical names combine without clashing | K | L/M | - | M1 |  |
| m1.mjs:105 | lower / mixed case keys inject as upper-case names only | K | L/M | - | M1 |  |
| m1.mjs:106 | --list shows the same upper-case names | K | L/M | - | M1 |  |
| m1.mjs:109 | keys colliding after upper-casing are an error | K | L/M | - | M1 |  |
| m1.mjs:113 | whitelisted keys (incl. prefixed *_HOST) shown as-is | K | L/M | - | M1 |  |
| m1.mjs:115 | PSWD, DBNAME, MAIL_TO redacted | K | L/M | - | M1 |  |
| m1.mjs:117 | stderr redacted too | K | L/M | - | M1 |  |
| m1.mjs:118 | adjacent secrets do not leak | K | L/M | - | M1 |  |
| m1.mjs:123 | short secrets masked on stdout; whitelisted HOST shown | K | L/M | - | M1 |  |
| m1.mjs:125 | short secrets masked on stderr | K | L/M | - | M1 |  |
| m1.mjs:128 | short secrets masked in the audit command | K | L/M | - | M1 |  |
| m1.mjs:133 | secret followed by an idle pause is masked (stdout, stderr) | K | L/M | - | M1 |  |
| m1.mjs:134 | secret written in two slow pieces is masked | K | L/M | - | M1 |  |
| m1.mjs:135 | overlapping secrets (abc, cdef) are masked as a whole | K | L/M | - | M1 |  |
| m1.mjs:136 | overlap inside other text | K | L/M | - | M1 |  |
| m1.mjs:137 | whitelisted value containing a secret fragment is shown as-is | K | L/M | - | M1 |  |
| m1.mjs:138 | the secret itself is still masked next to it | K | L/M | - | M1 |  |
| m1.mjs:139 | same with a pause in between | K | L/M | - | M1 |  |
| m1.mjs:141 | whitelisted value equal to a secret: the secret wins (masked) | K | L/M | - | M1 |  |
| m1.mjs:143 | overlap written in two pieces across a pause: one *** , no tail left | K | L/M | - | M1 |  |
| m1.mjs:144 | same, inside other text | K | L/M | - | M1 |  |
| m1.mjs:145 | whitelisted value written in two pieces across a pause is shown as-is | K | L/M | - | M1 |  |
| m1.mjs:146 | secret that turns out not to be part of the whitelisted value is masked | K | L/M | - | M1 |  |
| m1.mjs:147 | whitelisted value in three pieces, then the secret | K | L/M | - | M1 |  |
| m1.mjs:149 | equal whitelisted/secret value written in pieces: masked | K | L/M | - | M1 |  |
| m1.mjs:156 | 8 MB of dense output redacted in ${Date.now() - t0} ms (limit 30 s) | K | L/M | - | M1 |  |
| m1.mjs:162 | child exit code propagated | K | L/M | - | M1 |  |
| m1.mjs:164 | audit records logical names, command, exit code, time | K | L/M | - | M1 |  |
| m1.mjs:166 | audit log holds no secret values (masked in command) | K | L/M | - | M1 |  |
| m1.mjs:167 | audit log is mode 600 | K | L/M | - | M1 |  |
| m1.mjs:174 | unknown logical name: failure audited (exit 2, category, no name or command text) | K | L/M | - | M1 |  |
| m1.mjs:179 | usage error: failure audited, existing name kept | K | L/M | - | M1 |  |
| m1.mjs:181 | name collision: failure audited | K | L/M | - | M1 |  |
| m1.mjs:187 | secret given as logical name (${bogus.replace('gPass-7788', '<secret>')}): audited without it | K | L/M | - | M1 |  |
| m1.mjs:194 | invalid facility name: failure audited with exit code | K | L/M | - | M1 |  |
| m1.mjs:195 | failure records hold no secret values | K | L/M | - | M1 |  |
| m1.mjs:200 | existing 0644 log: appended and reset to 600 | K | L/M | - | M1 |  |
| m1.mjs:203 | new log: created as 600 | K | L/M | - | M1 |  |
| m1.mjs:207 | --list: one line per file with first @desc line | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:209 | --list: no nodes or variables at top level | K | L/M | - | M1 |  |
| m1.mjs:212 | --list file: doc block, lone ; is a blank line | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:213 | --list file: nodes with first desc line | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:214 | --list file: @remark, code comments, commented assignments, variables hidden | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:217 | --list node: prefixed variables with key meanings | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:219 | --list node: secret in @desc masked as whole token only | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:221 | --list output leaks no values | K | L/M | - | M1 |  |
| m1.mjs:223 | unknown node: error lists available nodes | K | L/M | - | M1 |  |
| m1.mjs:226 | --list file: overridden [DEFAULT] secret masked in file and node docs | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:229 | --list node: overridden [DEFAULT] secret masked | K | L/M | - | M1 | Chinese text is fixture data (@desc), kept |
| m1.mjs:230 | --list top level: overridden [DEFAULT] secret masked | K | L/M | - | M1 |  |
| m1.mjs:235 | shim finds store and code (../projects/VaneSecret) | R | L/M | - | M1 | R1 |
| m1.mjs:239 | shim via symlink works; WITH_SECRETS_ROOT not leaked | R | L/M | - | M1 | R1 |
| m1.mjs:242 | shim reports missing code with exit 127 | R | L/M | - | M1 | R2 |
| m1.mjs:244 | core exits when WITH_SECRETS_ROOT unset (no guessing) | R | L/M | - | M1 | R3 |
| e2e.mjs:55 | plaintext store: injection works, output redacted | K | L/M | - | M2 |  |
| e2e.mjs:59 | --init creates data key | K | L-sd | - | M2 |  |
| e2e.mjs:60 | --init warns that no backup exists | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:63 | data key file is mode 600 | K | L-sd | - | M2 |  |
| e2e.mjs:65 | data key unwraps via systemd-creds --user to 32 bytes | K | L-sd | - | M2 |  |
| e2e.mjs:67 | data key credential rejects a different credential name | K | L-sd | - | M2 |  |
| e2e.mjs:69 | --init refuses to overwrite existing key | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:73 | --export redis | K | L/M | - | M2 |  |
| e2e.mjs:75 | export file holds no secrets (PSWD = <hold>) | K | L/M | - | M2 |  |
| e2e.mjs:76 | export keeps plain values, inline comments, @remark | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:78 | --export refuses when an import file is pending | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:80 | --import redis (migration) | K | L/M | - | M2 |  |
| e2e.mjs:81 | import file shredded/removed | K | L/M | - | M2 |  |
| e2e.mjs:83 | store now has 2 ENC values, no plaintext secrets | K | L/M | - | M2 |  |
| e2e.mjs:84 | store keeps plain values, comments and docs | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:85 | local pre-import backup written | K | L/M | - | M2 |  |
| e2e.mjs:86 | import hints that auto backup is not set up | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:87 | import output leaks nothing | K | L/M | - | M2 |  |
| e2e.mjs:88 | imported store file is mode 600 | K | L/M | - | M2 |  |
| e2e.mjs:89 | encrypted store: injection decrypts, still redacted | K | L/M | - | M2 |  |
| e2e.mjs:90 | decrypted value has the right length | K | L/M | - | M2 |  |
| e2e.mjs:92 | --list works on encrypted store | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:103 | --import with edits | K | L/M | - | M2 |  |
| e2e.mjs:104 | import report lists added/updated/deleted key names | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:105 | omitted key reported as kept | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:106 | updated value injected | K | L/M | - | M2 |  |
| e2e.mjs:107 | deleted key gone, omitted key kept | K | L/M | - | M2 |  |
| e2e.mjs:108 | value with " ;" stored encrypted in [prod] | K | L/M | - | M2 |  |
| e2e.mjs:109 | quoted value length correct | K | L/M | - | M2 |  |
| e2e.mjs:110 | store still has no plaintext secrets | K | L/M | - | M2 |  |
| e2e.mjs:128 | rejects ${label}; store unchanged; import file kept | K | L/M | - | M2 |  |
| e2e.mjs:137 | ciphertext copied to another key fails (AAD binding) | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:143 | --new writes template with <fill> | K | L/M | - | M2 |  |
| e2e.mjs:144 | --new template has @desc, key block and the named node | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:145 | --new refuses an existing file | K | L/M | - | M2 |  |
| e2e.mjs:150 | new file imported and encrypted | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:157 | backup without a tty fails; passphrase not taken from args or env | K | L/M | - | M2 |  |
| e2e.mjs:159 | backup rejects short passphrase | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:161 | backup rejects mismatched passphrase | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:163 | first backup is the permanent base | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:165 | backup warns exactly when the dir is under /tmp or $TMPDIR | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:169 | later manual backup needs no passphrase | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:170 | backup key stored wrapped, passphrase not on disk | K | L-sd | - | M2 |  |
| e2e.mjs:178 | import triggers auto backup | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:180 | auto backups rotate to 19 | K | L/M | - | M2 |  |
| e2e.mjs:181 | base and manual backups kept | K | L/M | - | M2 |  |
| e2e.mjs:182 | bundle ${f.slice(0, 20)}… fully encrypted (no secrets, no hosts) | K | L/M | - | M2 |  |
| e2e.mjs:187 | verify: wrong passphrase rejected | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:189 | verify: right passphrase, all values decrypt | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:194 | after loss: injection fails | K | L/M | - | M2 |  |
| e2e.mjs:196 | restore from latest auto backup | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:197 | restored values decrypt with re-wrapped key | K | L/M | - | M2 |  |
| e2e.mjs:198 | restored the newest state | K | L/M | - | M2 |  |
| e2e.mjs:200 | after restore, backups work with the same passphrase (no prompt) | K | L/M | - | M2 |  |
| e2e.mjs:202 | restore over existing data moves it aside first | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:209 | import (before simulated crash) | K | L/M | - | M2 |  |
| e2e.mjs:214 | re-import of the same file reports no change | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:215 | re-import leaves the store byte-identical (unchanged values keep ciphertext) | K | L/M | - | M2 |  |
| e2e.mjs:216 | value after re-import is the intended one | K | L/M | - | M2 |  |
| e2e.mjs:217 | leftover temp file is ignored | K | L/M | - | M2 |  |
| e2e.mjs:222 | after import: neither the import file nor a .shredding file is left | K | L/M | - | M2 |  |
| e2e.mjs:228 | next admin command finishes leftover .shredding files and says so | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:230 | leftover .shredding files are gone | K | L/M | - | M2 |  |
| e2e.mjs:231 | store untouched by the sweep | K | L/M | - | M2 |  |
| e2e.mjs:235 | import refuses a file with NUL bytes; store unchanged | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:246 | auto backup failure: exit 3 with a clear warning | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:247 | auto backup failure: the import itself is complete | K | L/M | - | M2 |  |
| e2e.mjs:249 | auto backup failure: manual --backup <dir> recovers | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:257 | no dir given: backup goes to $TMPDIR/with-secrets-backup | K | L/M | - | M2 |  |
| e2e.mjs:258 | default (temp) backup dir warns | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:312 | sections left out of the import (empty, documented) are kept with their docs | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:313 | kept sections are reported | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:314 | keys matched without regard to case; kept plaintext secret encrypted | K | L/M | - | M2 |  |
| e2e.mjs:316 | renamed key re-encrypted under its new name; injection works (no case clash) | K | L/M | - | M2 |  |
| e2e.mjs:317 | kept empty section still listed with its doc | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:327 | rejects ${label}; store unchanged | K | L/M | - | M2 |  |
| e2e.mjs:332 | a new value resolves the clash (merged into one key) | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:342 | rejects ${label} (merged key set); store and import file unchanged | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:348 | same spelling in a node still overrides [DEFAULT] | K | L/M | - | M2 |  |
| e2e.mjs:354 | rejects a commented assignment with a spaced key; store unchanged | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:358 | rejects commented assignments with any number of words; store unchanged | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:362 | doc prose containing = (URL, CJK) is still accepted and shown | K | L/M | - | M2 | Chinese text is fixture data (@desc), kept |
| e2e.mjs:370 | rejects ${label} (no inherited "old value") | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:375 | legal names constructor / valueOf / __proto__ work as plain names | K | L/M | - | M2 |  |
| e2e.mjs:377 | --list handles them too | K | L/M | - | M2 |  |
| e2e.mjs:385 | ${point}: exit 1, store unchanged, import file kept, no temp files | K | L/M | test | M2 |  |
| e2e.mjs:388 | failure right after the commit: exit 3, store changed, import file still there (re-import is safe) | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:391 | re-running that import finishes it (no change) | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:395 | shred failure after commit: exit 3, store changed, says what is pending | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:397 | the unshredded file is kept as .shredding for retry | K | L/M | test | M2 |  |
| e2e.mjs:399 | next command retries and finishes the shred | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:403 | sweep skips a non-regular .shredding entry instead of failing | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:410 | corrupt backup config: import committed, exit 3, cause named | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:412 | --backup <dir> repairs the config | K | L/M | - | M2 |  |
| e2e.mjs:417 | 5 concurrent --export: exactly one wins, the file is intact | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:427 | 5 concurrent --init: exactly one key is created and it works | K | L-sd | - | M2 |  |
| e2e.mjs:434 | concurrent imports and backups all succeed (serialised by the lock) | K | L/M | - | M2 |  |
| e2e.mjs:436 | each bundle written by the concurrent run verifies (>= 4 new) | K | L/M | - | M2 |  |
| e2e.mjs:444 | crash while holding the lock: holder info left behind | K | L/M | test | M2 |  |
| e2e.mjs:446 | next command gets the lock at once (kernel released it) and says the last one did not finish | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:451 | 5 competitors after a crash: exactly one export, the rest refused | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:459 | while the lock is held: a short waiter gives up, nothing written | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:462 | a normal waiter proceeds after the holder releases | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:482 | backup started during a restore waits for it | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:485 | that backup holds the restored data (decrypted in the test: prod HOST = h21) and a data key | K | L/M | - | M2 |  |
| e2e.mjs:492 | crash while writing the first bundle: no bundle is visible | K | L/M | test | M2 |  |
| e2e.mjs:494 | next backup becomes the base; the partial file is cleaned up | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:499 | (rotation full: 19 auto bundles) | K | L/M | test | M2 |  |
| e2e.mjs:502 | crash during an auto backup (import committed): partial file is not a bundle, none rotated out | K | L/M | test | M2 |  |
| e2e.mjs:506 | after it: 19 valid auto bundles, no partial file counted or left | K | L/M | test | M2 |  |
| e2e.mjs:522 | damaged auto files are reported, not counted, not deleted; 19 intact remain | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:524 | all 19 counted bundles decrypt (checked in the test) | K | L/M | - | M2 |  |
| e2e.mjs:532 | damaged files named as base do not count: a new base is made | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:539 | --new-password with a failed bundle: passphrase and dir settings unchanged | K | L/M | test | M2 |  |
| e2e.mjs:542 | bundle written but new passphrase not saved: exit 3, old key still in use | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:544 | bundle written but new dir not saved: exit 3, config unchanged | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:547 | auto backups still use the old passphrase | K | L/M | test | M2 |  |
| e2e.mjs:555 | restore failing at ${point}: exit 1, store unchanged and usable | K | L/M | test | M2 |  |
| e2e.mjs:559 | crash in the middle of a restore leaves the journal | K | L/M | test | M2 |  |
| e2e.mjs:561 | next command completes the restore (roll forward) | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:564 | --undo-restore puts back the previous store (values and key) | K | L/M | test | M2 |  |
| e2e.mjs:566 | restore again | K | L/M | test | M2 |  |
| e2e.mjs:569 | a crashed undo is completed by the next command | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:573 | bookkeeping failure after the swap: exit 5, store already restored, journal kept | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:577 | next command finishes the bookkeeping | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:581 | and that restore can be undone | K | L/M | test | M2 |  |
| e2e.mjs:585 | (docs shown while everything decrypts) | K | L/M | test | M2 |  |
| e2e.mjs:589 | one damaged ciphertext: docs hidden, names shown, notice given | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:593 | data key unavailable: docs hidden with the reason | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:595 | (docs back once the key is back) | K | L/M | - | M2 |  |
| e2e.mjs:603 | journal cannot be removed: exit 5 (not 0), journal kept | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:605 | while it persists, other management commands are refused (exit 5, nothing written) | K | L/M | test | M2 |  |
| e2e.mjs:607 | once it clears, the next command finishes the restore and proceeds | E | L/M | test | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:610 | and the restore can be undone | K | L/M | test | M2 |  |
| e2e.mjs:620 | (old base damaged: verify fails) | K | L/M | - | M2 |  |
| e2e.mjs:623 | passphrase change over a damaged old-passphrase base: a new, verifiable base is made; the old file is kept | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:626 | the new base opens with the new passphrase | K | L/M | - | M2 |  |
| e2e.mjs:633 | new passphrase in the auto dir: new base; old-passphrase bundles reported as unverifiable | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:637 | old-passphrase autos are neither counted nor rotated out; 3 new autos added | K | L/M | - | M2 |  |
| e2e.mjs:638 | the new autos open with the new passphrase | K | L/M | - | M2 |  |
| e2e.mjs:648 | ENC values but no data key: backup refused (exit 1), no bundle, settings unchanged | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:652 | with the key back, the first real backup becomes the base | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| e2e.mjs:659 | (crafted: opens with the current passphrase, but has no data key) | K | L/M | - | M2 |  |
| e2e.mjs:661 | an unrestorable base does not count: a restorable base is made | E | L/M | - | M2 | Chinese tool output → matched by message ID |
| relocate.mjs:41 | (synthetic old layout works through the old shim) | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:48 | target exists and is not empty: exit 12, code not moved, no backup made | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:51 | entry backup fails: exit 15, code not moved | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:53 | source missing: exit 10 | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:58 | ${what} fails: exit ${code}, code and entry restored, old layout works | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:65 | move: code relocated, entry switched, --list works | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:66 | move: the old entry is kept as bin.bak-* | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:68 | check: layout and entry verified | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:71 | check: reports an entry that differs from shims/ | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:79 | rollback with an incomplete backup dir: exit 11, nothing changed | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:81 | rollback whose check fails: exit 22, new layout restored and working | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:83 | rollback: old layout and old entry back, --list works | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:91 | (bash-only old layout works) | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:93 | bash-only layout, install fails: exit 21, code moved back, entry restored exactly (only bash), --list works | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:96 | bash-only layout, post-switch check fails: restored exactly | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:100 | bash-only layout: move succeeds; the backup holds just the bash entry | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:102 | rollback to bash-only, entry step fails: new layout restored and working | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| relocate.mjs:104 | rollback to bash-only: exactly the old entry (no .ps1/.cmd left), --list works | R | L/M | - | M4 | R5 (Node layout relocation → install.sh) |
| echo-check.mjs (whole) | passphrase not echoed (typed after the prompt) | E | L/M | - | M2 | prompt matched by message ID |

Counts (assertion statements; a statement in a loop counts once):
- m1.mjs: K 55 · E 0 · R 4
- e2e.mjs: K 78 · E 66 · R 0
- relocate.mjs: K 0 · E 0 · R 18

## M4 (install, release, cleanup)

`go test ./test/ -run 'Install_'` (release build only; no key backend needed).

| ID | Check |
|---|---|
| M4.I1–I8 | first install layout (version dir, `current`, relative `bin/with-secrets` and `bin/gseal`), config written once (mode 600) and never overwritten (differences shown), upgrade side by side with `previous`, `--check`, `--rollback`, a reused version with another executable refused, default prefix `~/.local` for every non-root user |
| M4.R1 | replacement R1 on the installed layout: two levels of links (`~/.local/bin` -> `<prefix>/bin` -> `current`), store from the config, no `GSEAL_*` / `WITH_SECRETS_*` in the child |
| M4.R2 | replacement R2: `current` pointing to a missing version: `--check` FAILs (non-zero), calling the entry exits 127 |
| M4.L1–L4, U1–U4 | `--link-store-bin`: `<store>/bin` copied to `bin.bak-*` first, the old path works with only HOME and PATH (injection, `--list`), `--check` covers it; uninstall removes program and links, keeps store, config and backups, puts `<store>/bin` back and restores an entry link the install had replaced |
| M4.F1–F4 | replacement R5: a failure at every install step (binary, switch, previous, links, config, store-bin, verify) and in `--rollback` puts prefix, stores and config back exactly (exit 1); a store the old path would not reach is not linked |
| M4.V1–V3 | (review M4-005) store-bin and verify steps: the fault is really reached and everything is put back; the old path is checked as a cron job calls it (only HOME and PATH=/usr/bin:/bin, exact store path, on first and repeated installs): a config only in `GSEAL_CONFIG` is refused with the old entry kept |
| M4.I9 | (review M4-001) installs of one prefix are serialised (lock): two overlapping upgrades leave `previous` at the version active before the last switch |
| M4.K1–K5 | (review M4-002) `--check` fails for a removed store entry (recorded store), a missing rollback target and a config that does not load |
| M4.G1–G3 | (review M4-003) the config is created atomically with mode 600: a failure while writing or setting the mode leaves no file and no directory; a config created meanwhile is kept |
| M4.U5–U7 | (review M4-004) uninstall restores only the entry, from the backup recorded by the switch (not the newest-named one), keeps files added to `bin/` and other backups; with the backup missing it removes nothing (exit 1) and the entry keeps working; a store inside the prefix (or the reverse) is refused |
| M4.I10–I12 | (review M4-001, round 2) a holder killed while holding the lock leaves nothing to take over (kernel flock; flock(1) is a precondition of this test, CI installs it on macOS); without flock (forced with `GSEAL_INSTALL_NO_FLOCK`) a dead holder's lock is reported and never taken over, and installs are still serialised |
| M4.I13–I14 | (review M4-001, round 3) the lock is the prefix directory itself (never deleted): an uninstall during an install waits; installs after an uninstall are still serialised |
| M4.I15–I16 | (review M4-001, round 4) one lock for every process: a mkdir lock in /tmp named after the canonical prefix (flock only serialises taking over a dead holder's lock); a process with flock and one without (both orders) are serialised; a first install that fails and removes the prefix it made does not let the waiting install and a new one in together |
| M4.I17 | (review M4-001, round 5) a failing install removes the directories it made before releasing the lock; the next install, taking the lock meanwhile, completes |
| M4.U14 | (review M4-004, round 5) every config path an install used is recorded; uninstall keeps what any of them links to, also from a session without `GSEAL_CONFIG` |
| M4.U15 | (review M4-004, round 6) uninstall removes only the exact file names install writes in `state/`; files added later (also temp-file-like names) and an unrecorded config linking to one are kept |
| M4.U12–U13 | (review M4-004, round 4) a config file that is a symlink into `<prefix>/lib/gseal`: install refused; uninstall never removes the file it links to |
| M4.K7 | (review M4-002, round 3) a config path that became a directory fails `--check` |
| M4.G7, U10–U11 | (review M4-004, round 3) path overlaps are compared canonically (`..`, symlinks); an entry link uninstall cannot remove stops it (exit 1, program kept, entry works) |
| M4.K6 | (review M4-002, round 2) a recorded store whose `bin/` did not exist before: a removed entry FAILs `--check` |
| M4.G4–G6 | (review M4-003, round 2) a directory at the config path (before or created meanwhile) and a config path inside `<prefix>/lib/gseal` are refused; nothing is written |
| M4.U8–U9 | (review M4-004, round 2) stores with no old entry or no `bin/`: uninstall removes the link (and the empty `bin/` it made); files in `state/` that install did not write are kept |
| M4.H1 | (review M4-009) a failure after the replaced entry link was recorded puts the link back and leaves no state |
| M4.C2 | (review M4-007) `tools/check-history.sh --tree` finds what M4.C1 finds (name, e-mail, path, host, IP), leaves out vendor/ and testdata/norm/, exits 2 (never "clean") when it cannot read its input; its allow lists equal M4.C1's |
| M4.D1–D2 | (review M4-008) README quick start covers both key backends; SECURITY.md states that plain-text values are not protected at rest |
| M4.P1–P5 | `tools/release.sh`: four archives (linux/darwin x amd64/arm64) and verifying SHA256SUMS; an extracted archive installs its own executable without go; a source tree builds with go (version from `VERSION`) |
| M4.C1 | no internal names (checked by SHA-256), personal paths, host names other than `*.invalid` and the project's public homes, IP addresses other than the fixtures', or e-mail addresses in the repository |

CI (`.github/workflows/ci.yml`) runs every suite above on ubuntu-latest and
macos-latest with `GSEAL_TEST_BACKEND=testfile`; the systemd-creds suites and
the Go -> VaneSecret interop are skipped there with the reason in the log and
are run on a Linux machine with systemd >= 256. On Linux the job installs
Node 24 (Unicode 16 or newer) and runs `TestAgainstNode` unchanged with
`GSEAL_REQUIRE_NODE=1` (every code point of the tables compared).

Publishing: the development branch keeps its history; a public branch is made
with a single commit holding the final tree and checked with
`tools/check-history.sh <ref>` (the M4.C1 checks on every reachable commit)
before it is pushed.

## M5 (CI fixes)

- macOS: BSD `script(1)` sends ^D to the pseudo-terminal as soon as its standard input ends, so typed-ahead input reached the program with a ^D in front (the first passphrase read as empty). The terminal-input helper (`runTyped`) keeps the input open until the command has finished on macOS; Linux is unchanged.
- e2e_L482 waited a fixed 2.5 s and assumed the restore then held the lock; a fast runner finished the restore first. It now waits until the lock's holder info names `--restore` before starting the backup. The assertions are unchanged.
- The workflows use actions/checkout@v5, setup-go@v6, setup-node@v5 (Node 24).
