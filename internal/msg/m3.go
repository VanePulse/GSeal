package msg

// Messages of the M3 commands (--apply-policy, --set, --rotate-datakey,
// doctor) and of the passphrase key backend.
const (
	UnknownBackend     ID = "unknown-backend"
	PassCredBad        ID = "pass-cred-bad"
	PassCredName       ID = "pass-cred-name"
	PromptStorePass    ID = "prompt-store-pass"
	PromptNewStorePass ID = "prompt-new-store-pass"
	StorePassWrong     ID = "store-pass-wrong"

	OpApply  ID = "op-apply"
	OpRotate ID = "op-rotate"

	ApplyFile      ID = "apply-file"
	ApplyEncrypt   ID = "apply-encrypt"
	ApplyDecrypt   ID = "apply-decrypt"
	ApplyNoDecrypt ID = "apply-no-decrypt"
	ApplyTotal     ID = "apply-total"
	ApplyDryRun    ID = "apply-dry-run"
	ApplyNothing   ID = "apply-nothing"
	ApplyDone      ID = "apply-done"
	ApplySkipped   ID = "apply-skipped"
	ApplyAside     ID = "apply-aside"
	ChangedPending ID = "changed-pending"
	ChangedHint    ID = "changed-hint"

	SetBadTarget ID = "set-bad-target"
	SetNoFile    ID = "set-no-file"
	SetNoSection ID = "set-no-section"
	SetNoKey     ID = "set-no-key"
	SetAmbiguous ID = "set-ambiguous"
	SetEmpty     ID = "set-empty"
	PromptValue  ID = "prompt-value"
	SetDone      ID = "set-done"
	SetChanged   ID = "set-changed"
	StoredEnc    ID = "stored-encrypted"
	StoredPlain  ID = "stored-plain"

	RotateNoKey  ID = "rotate-no-key"
	RotateCheck  ID = "rotate-check"
	RotateNotRun ID = "rotate-not-started"
	RotateDone   ID = "rotate-done"
	RotateOld    ID = "rotate-old"

	DocOK         ID = "doc-ok"
	DocWarn       ID = "doc-warn"
	DocFail       ID = "doc-fail"
	DocSummary    ID = "doc-summary"
	DocConfig     ID = "doc-config"
	DocConfigNone ID = "doc-config-none"
	DocConfigBad  ID = "doc-config-bad"
	DocStore      ID = "doc-store"
	DocVersion    ID = "doc-version"
	DocVersionNew ID = "doc-version-new"
	DocNotOwned   ID = "doc-not-owned"
	DocDirMode    ID = "doc-dir-mode"
	DocFileModes  ID = "doc-file-modes"
	DocModesOK    ID = "doc-modes-ok"
	DocBackend    ID = "doc-backend"
	DocSystemd    ID = "doc-systemd"
	DocSystemdOld ID = "doc-systemd-old"
	DocSystemdNo  ID = "doc-systemd-missing"
	DocNoDataKey  ID = "doc-no-datakey"
	DocNoKeyEnc   ID = "doc-no-datakey-enc"
	DocDataKey    ID = "doc-datakey"
	DocDataKeyPw  ID = "doc-datakey-passphrase"
	DocDataKeyBad ID = "doc-datakey-bad"
	DocValues     ID = "doc-values"
	DocValuesBad  ID = "doc-values-bad"
	DocValuesSkip ID = "doc-values-skip"
	DocPolicyOK   ID = "doc-policy-ok"
	DocPolicyDiff ID = "doc-policy-diff"
	DocPolicyBad  ID = "doc-policy-bad"
	DocNoBackup   ID = "doc-no-backupkey"
	DocBackupKey  ID = "doc-backupkey"
	DocBackupKeyX ID = "doc-backupkey-bad"
	DocBkDir      ID = "doc-backup-dir"
	DocBkDirNone  ID = "doc-backup-dir-missing"
	DocBkDirTemp  ID = "doc-backup-dir-temp"
	DocBkConfBad  ID = "doc-backup-conf-bad"
	DocLastOK     ID = "doc-last-ok"
	DocLastOld    ID = "doc-last-old"
	DocLastOther  ID = "doc-last-other"
	DocLastBad    ID = "doc-last-damaged"
	DocLastNone   ID = "doc-last-none"
	DocLastNoKey  ID = "doc-last-unchecked"
	DocJournal    ID = "doc-journal"
	DocShredding  ID = "doc-shredding"
	DocImports    ID = "doc-imports"
	DocClean      ID = "doc-clean"
	DocAudit      ID = "doc-audit"
	DocAuditNone  ID = "doc-audit-none"
	DocAuditMode  ID = "doc-audit-mode"
	DocAuditOwner ID = "doc-audit-owner"
	DocAuditOff   ID = "doc-audit-off"

	DocUnreadable    ID = "doc-unreadable"
	DocPartial       ID = "doc-partial"
	ReasonMissing    ID = "reason-missing"
	ReasonPerm       ID = "reason-permission"
	ReasonReadErr    ID = "reason-read-error"
	ReasonNotRegular ID = "reason-not-regular"

	DocVersionBad       ID = "doc-version-bad"
	DocPolicyFileBad    ID = "doc-policy-file-bad"
	DocPolicyCfgBad     ID = "doc-policy-config-bad"
	DocBackupKeyBadJSON ID = "doc-backupkey-bad-json"

	VersionLine ID = "version-line"

	ListEnvFailed ID = "list-env-failed"
	DocListFailed ID = "doc-list-failed"

	CfgSafeFile       ID = "cfg-safe-file"
	CfgSafeLine       ID = "cfg-safe-line"
	CfgKindRead       ID = "cfg-kind-read"
	CfgKindSyntax     ID = "cfg-kind-syntax"
	CfgKindUnknownSec ID = "cfg-kind-unknown-section"
	CfgKindUnknownKey ID = "cfg-kind-unknown-key"
	CfgKindDup        ID = "cfg-kind-dup"
	CfgKindBadValue   ID = "cfg-kind-bad-value"
)

var m3Table = map[ID]string{
	UnknownBackend:     "unknown key backend %s (systemd-creds or passphrase)",
	PassCredBad:        "not a valid passphrase credential",
	PassCredName:       "credential is not for %s",
	PromptStorePass:    "Enter the store passphrase: ",
	PromptNewStorePass: "Set the store passphrase (protects the data key; at least 12 characters): ",
	StorePassWrong:     "wrong store passphrase",

	OpApply:  "apply-policy",
	OpRotate: "rotate-datakey",

	ApplyFile:      "%s: %d to encrypt, %d to decrypt",
	ApplyEncrypt:   "  encrypt [%s] %s",
	ApplyDecrypt:   "  decrypt [%s] %s",
	ApplyNoDecrypt: "  decrypt [%s] %s (not done: needs --allow-decrypt)",
	ApplyTotal:     "total: %d to encrypt, %d to decrypt in %d file(s)",
	ApplyDryRun:    "dry run: nothing changed",
	ApplyNothing:   "the store already matches the policy; nothing changed",
	ApplyDone:      "policy applied: %d value(s) encrypted, %d decrypted in %d file(s)",
	ApplySkipped:   "%d value(s) left encrypted: the policy no longer asks for them, run with --allow-decrypt to decrypt them",
	ApplyAside:     "previous files saved in %s",
	ChangedPending: "!!! the store is changed (committed, exit code %d), but these follow-up steps are not complete:",
	ChangedHint:    "!!! after fixing it, run with-secrets --backup",

	SetBadTarget: "--set needs <file>.<node> <KEY>",
	SetNoFile:    "%s does not exist (add --create to create it)",
	SetNoSection: "%s has no node [%s] (add --create to create it)",
	SetNoKey:     "[%s] of %s has no key %s (add --create to add it)",
	SetAmbiguous: "[%s] of %s has keys %s that differ only in case; fix it with --export / --import first",
	SetEmpty:     "empty value; nothing changed",
	PromptValue:  "Value for %s.%s %s: ",
	SetDone:      "set %s.%s %s (%s)",
	SetChanged:   "  %s",
	StoredEnc:    "stored encrypted",
	StoredPlain:  "stored as plain text",

	RotateNoKey:  "there is no data key to rotate (run with-secrets --init)",
	RotateCheck:  "self-check failed: %s",
	RotateNotRun: "rotation not started; the store is unchanged: %s",
	RotateDone:   "data key rotated: %d encrypted value(s) in %d file(s) re-encrypted with the new key",
	RotateOld:    "the previous files and the old data key are in %s (older local copies and backups keep their own key)",

	DocOK:         "OK    %s",
	DocWarn:       "WARN  %s",
	DocFail:       "FAIL  %s",
	DocSummary:    "doctor: %d OK, %d WARN, %d FAIL",
	DocConfig:     "config: %s",
	DocConfigNone: "config: %s (not present, defaults in use)",
	DocConfigBad:  "%s",
	DocStore:      "store: %s (from %s)",
	DocVersion:    "store format version %d",
	DocVersionNew: "store format version %d is newer than this build supports (%d): upgrade with-secrets",
	DocNotOwned:   "%s is not owned by the current user",
	DocDirMode:    "%s is accessible by other users (mode %s); run chmod 700 on it",
	DocFileModes:  "files readable by other users (should be mode 600): %s",
	DocModesOK:    "permissions: store files are private to the current user",
	DocBackend:    "key backend: %s",
	DocSystemd:    "systemd-creds %d supports --user",
	DocSystemdOld: "systemd-creds %d is too old (--user needs systemd 256 or newer)",
	DocSystemdNo:  "systemd-creds not found: %s",
	DocNoDataKey:  "no data key yet (with-secrets --init creates it; not needed while nothing is encrypted)",
	DocNoKeyEnc:   "no data key, but %d value(s) are encrypted: restore it with with-secrets --restore <bundle>",
	DocDataKey:    "data key unwraps",
	DocDataKeyPw:  "data key is protected by the store passphrase (doctor does not ask for it)",
	DocDataKeyBad: "data key: %s",
	DocValues:     "%d encrypted value(s) in %d file(s) decrypt",
	DocValuesBad:  "values that do not decrypt: %s",
	DocValuesSkip: "encrypted values not checked (data key not unlocked): %d",
	DocPolicyOK:   "stored values match the encryption policy",
	DocPolicyDiff: "%d value(s) to encrypt, %d to decrypt by the policy (see with-secrets --apply-policy --dry-run)",
	DocPolicyBad:  "encryption policy: %s",
	DocNoBackup:   "automatic backup is not set up (run with-secrets --backup <dir>)",
	DocBackupKey:  "backup key unwraps",
	DocBackupKeyX: "backup key: %s",
	DocBkDir:      "backup directory: %s",
	DocBkDirNone:  "backup directory %s does not exist yet",
	DocBkDirTemp:  "backup directory %s is a temporary directory (wiped on reboot, lost with the machine)",
	DocBkConfBad:  "%s",
	DocLastOK:     "latest backup %s (%s) opens with the current passphrase and is restorable",
	DocLastOld:    "latest backup %s is from %s, more than %d days ago",
	DocLastOther:  "latest backup %s was made with another passphrase (check it with --verify-backup)",
	DocLastBad:    "latest backup %s is damaged or not restorable",
	DocLastNone:   "no backup in %s",
	DocLastNoKey:  "latest backup %s (%s) not verified (backup key not unlocked)",
	DocJournal:    "an interrupted %s is pending (journal %s): run any management command to complete it",
	DocShredding:  "import files left half shredded: %s (the next management command finishes them)",
	DocImports:    "import files waiting in %s (they may hold plain-text secrets): %s",
	DocClean:      "no interrupted operation, no pending import files",
	DocAudit:      "audit log %s is private to the current user",
	DocAuditNone:  "no audit log yet",
	DocAuditMode:  "audit log %s has mode %s (should be 600)",
	DocAuditOwner: "audit log %s is not owned by the current user",
	DocAuditOff:   "audit log disabled in the config",

	DocUnreadable:    "facility files that cannot be read: %s",
	DocPartial:       "values and the encryption policy not checked: not every facility file could be read",
	ReasonMissing:    "missing, e.g. a broken link",
	ReasonPerm:       "permission denied",
	ReasonReadErr:    "read error",
	ReasonNotRegular: "not a regular file",

	DocVersionBad:       "store format version file %s is not a valid version number",
	DocPolicyFileBad:    "%s.ini: invalid @encrypt (see with-secrets --policy %s)",
	DocPolicyCfgBad:     "config %s: invalid value for encrypt.keys",
	DocBackupKeyBadJSON: "the unwrapped backup key is not in the expected format",

	VersionLine: "with-secrets %s (GSeal)",

	ListEnvFailed: "cannot list the facility files in %s: %s",
	DocListFailed: "%s",

	CfgSafeFile:       "config %s: %s",
	CfgSafeLine:       "config %s line %d: %s",
	CfgKindRead:       "cannot be read%s",
	CfgKindSyntax:     "not a [section] or key = value line%s",
	CfgKindUnknownSec: "unknown section%s",
	CfgKindUnknownKey: "unknown key in %s",
	CfgKindDup:        "%s is set twice",
	CfgKindBadValue:   "invalid value for %s",
}

func init() {
	for id, text := range m3Table {
		if _, dup := table[id]; dup {
			panic("msg: duplicate id " + string(id))
		}
		table[id] = text
	}
}
