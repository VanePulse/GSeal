package msg

// Messages of the management commands (--init, --new, --export, --import,
// --backup, --verify-backup, --restore, --undo-restore).
const (
	Unexpected   ID = "unexpected"
	UnknownCmd   ID = "unknown-command"
	FaultAt      ID = "fault-at"
	ShortWrite   ID = "short-write"
	ShortWriteIn ID = "short-write-injected"

	MissingFile ID = "missing-file"
	BadFile     ID = "bad-file"
	BadNode     ID = "bad-node"

	ShredSkip   ID = "shred-skip"
	ShredFailed ID = "shred-failed"
	SweepDone   ID = "sweep-done"
	SweepFailed ID = "sweep-failed"

	LockFailed  ID = "lock-failed"
	LockWaiting ID = "lock-waiting"
	LockBusy    ID = "lock-busy"
	LockStale   ID = "lock-stale"

	OpRestore        ID = "op-restore"
	OpUndo           ID = "op-undo"
	RecoverFailed    ID = "recover-failed"
	RecoverDone      ID = "recover-done"
	SwapStuck        ID = "swap-stuck"
	SwapRolledBack   ID = "swap-rolled-back"
	SwapFinishFailed ID = "swap-finish-failed"

	PromptNoTTY     ID = "prompt-no-tty"
	PromptCancelled ID = "prompt-cancelled"
	PromptNew       ID = "prompt-new"
	PromptAgain     ID = "prompt-again"
	PromptPass      ID = "prompt-pass"
	PassMismatch    ID = "pass-mismatch"
	PassShort       ID = "pass-short"

	BundleNotBundle  ID = "bundle-not-bundle"
	BundleHeaderBad  ID = "bundle-header-bad"
	BundleOpenFailed ID = "bundle-open-failed"
	BundleKDFBad     ID = "bundle-kdf-bad"
	BundleDamaged    ID = "bundle-damaged"
	BundleOthers     ID = "bundle-others"
	BackupConfBad    ID = "backup-conf-bad"
	BackupRefused    ID = "backup-refused"
	BackupInTemp     ID = "backup-in-temp"
	AutoNotSetUp     ID = "auto-not-set-up"
	AutoDone         ID = "auto-done"
	AutoFailed       ID = "auto-failed"
	KindBase         ID = "kind-base"
	KindAuto         ID = "kind-auto"
	KindManual       ID = "kind-manual"

	InitExists   ID = "init-exists"
	InitDone     ID = "init-done"
	InitNoBackup ID = "init-no-backup"

	ImportPending   ID = "import-pending"
	ImportExists    ID = "import-exists"
	NewExists       ID = "new-exists"
	NewTemplate     ID = "new-template"
	NewDone         ID = "new-done"
	NewNext         ID = "new-next"
	ExportMissing   ID = "export-missing"
	ExportDone      ID = "export-done"
	ExportNext      ID = "export-next"
	ImportNoFile    ID = "import-no-file"
	ImportNUL       ID = "import-nul"
	ImpCommented    ID = "imp-commented"
	ImpBadSection   ID = "imp-bad-section"
	ImpDupSection   ID = "imp-dup-section"
	ImpUnrecognized ID = "imp-unrecognized"
	ImpKeyFirst     ID = "imp-key-before-section"
	ImpBadKey       ID = "imp-bad-key"
	ImpDupKey       ID = "imp-dup-key"
	ImpCommentGone  ID = "imp-comment-removed"
	ImpCaseMerged   ID = "imp-case-merged"
	ImpRenamed      ID = "imp-renamed"
	ImpFill         ID = "imp-fill"
	ImpDeleteNone   ID = "imp-delete-missing"
	ImpHoldAmbig    ID = "imp-hold-ambiguous"
	ImpHoldNone     ID = "imp-hold-none"
	ImpValueErr     ID = "imp-value-error"
	ImpStoreClash   ID = "imp-store-clash"
	ImpSectionKept  ID = "imp-section-kept"
	ImpKeysKept     ID = "imp-keys-kept"
	ImpKeyErr       ID = "imp-key-error"
	ImpFailed       ID = "imp-failed"
	ItemBad         ID = "item-bad"
	ItemNote        ID = "item-note"
	ImpSelfCheck    ID = "imp-self-check"
	ImpCaseClash    ID = "imp-case-clash"
	ImpBothQuotes   ID = "imp-both-quotes"
	ImpDoneBackup   ID = "imp-done-backup"
	ImpDoneNew      ID = "imp-done-new"
	ImpFileDeleted  ID = "imp-file-deleted"
	RepLine         ID = "rep-line"
	RepAdded        ID = "rep-added"
	RepUpdated      ID = "rep-updated"
	RepDeleted      ID = "rep-deleted"
	RepNone         ID = "rep-none"
	RepSep          ID = "rep-sep"
	ImpShredLeft    ID = "imp-shred-left"
	ImpShredErr     ID = "imp-shred-error"
	Committed       ID = "committed-incomplete"
	PendingItem     ID = "pending-item"
	CommittedHint   ID = "committed-hint"

	BackupKeyGone      ID = "backup-key-gone"
	BackupConfUsing    ID = "backup-conf-using"
	BackupDone         ID = "backup-done"
	BackupPassNotSaved ID = "backup-pass-not-saved"
	BackupDirNotSaved  ID = "backup-dir-not-saved"
	BackupIncomplete   ID = "backup-incomplete"
	BackupRetryHint    ID = "backup-retry-hint"
	BackupAutoDir      ID = "backup-auto-dir"

	MissingBundle   ID = "missing-bundle"
	VerifyBundle    ID = "verify-bundle"
	VerifyCounts    ID = "verify-counts"
	VerifyOK        ID = "verify-ok"
	PayloadBadName  ID = "payload-bad-name"
	PayloadNoKey    ID = "payload-no-key"
	PayloadNoDecr   ID = "payload-no-decrypt"
	RestoreCheck    ID = "restore-check-failed"
	RestoreKeyDiff  ID = "restore-key-differs"
	RestoreBkBad    ID = "restore-backupkey-bad"
	RestoreNotStart ID = "restore-not-started"
	RestoreAside    ID = "restore-aside"
	RestoreDone     ID = "restore-done"
	RestoreRebound  ID = "restore-rebound"
	UndoNone        ID = "undo-none"
	UndoDone        ID = "undo-done"

	TestCredBad  ID = "testcred-bad"
	TestCredName ID = "testcred-name"
)

var adminTable = map[ID]string{
	Unexpected:   "error: %s",
	UnknownCmd:   "unknown command %s",
	FaultAt:      "injected fault at %s",
	ShortWrite:   "short write",
	ShortWriteIn: "short write (injected)",

	MissingFile: "missing file name (e.g. redis)",
	BadFile:     "invalid file name: %s",
	BadNode:     "invalid node name: %s",

	ShredSkip:   "skipped a non-regular file (left as is): %s",
	ShredFailed: "could not shred %s (kept; the next management command retries): %s",
	SweepDone:   "finished shredding an import file left by an interrupted run: %s (that import is in the store)",
	SweepFailed: "cleaning up %s failed (will retry later): %s",

	LockFailed:  "cannot lock %s: %s",
	LockWaiting: "waiting for another management command to finish (%s, pid %s)...",
	LockBusy:    "another management command is running (%s, pid %s); try again later",
	LockStale:   "the previous management command (%s, pid %s, %s) did not finish normally; completing what it left before continuing",

	OpRestore:        "restore",
	OpUndo:           "undo-restore",
	RecoverFailed:    "the last %s was interrupted and could not be completed automatically: %s (journal %s kept)",
	RecoverDone:      "the last %s (%s) was interrupted; completed automatically from its journal",
	SwapStuck:        "failed midway and could not roll back: %s / %s; the next management command completes it from the journal",
	SwapRolledBack:   "failed midway; rolled back to the previous state, nothing changed: %s",
	SwapFinishFailed: "all files are swapped, but finishing up did not complete: %s; the next management command finishes it from the journal",

	PromptNoTTY:     "the passphrase must be typed in an interactive terminal (it is never taken from arguments or environment variables)",
	PromptCancelled: "cancelled",
	PromptNew:       "Set the backup passphrase (at least 12 characters): ",
	PromptAgain:     "Enter it again: ",
	PromptPass:      "Enter the backup passphrase (%s backup of %s): ",
	PassMismatch:    "the two passphrases do not match",
	PassShort:       "passphrase too short: at least %d characters",

	BundleNotBundle:  "not a with-secrets backup bundle",
	BundleHeaderBad:  "backup bundle header is damaged",
	BundleOpenFailed: "wrong passphrase or damaged backup bundle",
	BundleKDFBad:     "backup bundle has unsupported key derivation parameters",
	BundleDamaged:    "ignoring a damaged backup file (not used as base, not counted for rotation; delete it once checked): %s",
	BundleOthers:     "%s holds %d bundle(s) made with another passphrase: they cannot be verified with the current one, so they are not used as base or rotated, and are never deleted (check them with --verify-backup and their passphrase)",
	BackupConfBad:    "backup directory setting is damaged: %s (run with-secrets --backup <dir> to set it again)",
	BackupRefused:    "backup not written: its content could not be fully restored (%s). Repair the data key first (with-secrets --restore <bundle>), then back up",
	BackupInTemp:     "backup is in %s: a temporary directory is wiped on reboot and stays on this machine, so it cannot save you when the machine breaks. Use with-secrets --backup <external dir>",
	AutoNotSetUp:     "automatic backup is not set up: run with-secrets --backup [<dir>] to set a passphrase; every import then backs up automatically",
	AutoDone:         "backed up automatically (%s): %s",
	AutoFailed:       "automatic backup not completed: %s",
	KindBase:         "base, kept forever",
	KindAuto:         "auto",
	KindManual:       "manual, kept forever",

	InitExists:   "data key already exists; refusing to overwrite it (values already encrypted would no longer decrypt)",
	InitDone:     "data key created: %s (bound to this machine and user)",
	InitNoBackup: "no backup yet: if this machine breaks, nothing can be recovered. Run with-secrets --backup [<external dir>] now",

	ImportPending: "import file already exists and may hold changes not yet imported: %s",
	ImportExists:  "import file already exists: %s",
	NewExists:     "%s already exists; use with-secrets --export %s to change it",
	// Arguments: facility, node, date.
	NewTemplate: "; @desc <file description: system / purpose>\n" +
		";\n" +
		"; Keys:\n" +
		";   HOST  server address\n" +
		";   PORT  port\n" +
		";   USER  login account\n" +
		";   PSWD  login password\n" +
		"; @remark generated by with-secrets --new on %[3]s; fill in, then run with-secrets --import %[1]s\n" +
		"\n" +
		"[%[2]s]\n" +
		"; @desc <node description: environment / permissions>\n" +
		"HOST = <fill>\n" +
		"PORT = <fill>\n" +
		"USER = <fill>\n" +
		"PSWD = <fill>\n",
	NewDone:         "template written: %s",
	NewNext:         "fill in <fill> and the descriptions, then run: with-secrets --import %s",
	ExportMissing:   "%s does not exist (for a new file use with-secrets --new %s)",
	ExportDone:      "exported: %s (%d secret value(s) shown as <hold>; the file contains no secrets)",
	ExportNext:      "after editing, run: with-secrets --import %s",
	ImportNoFile:    "no import file: %s (run --export or --new first)",
	ImportNUL:       "import file is damaged (contains NUL bytes); nothing written: %s\n  delete it, run with-secrets --export %s again, then edit and import",
	ImpCommented:    "line %d: a comment looks like KEY = value (possibly an old credential); delete it",
	ImpBadSection:   "line %d: invalid section name [%s]",
	ImpDupSection:   "line %d: section [%s] appears twice",
	ImpUnrecognized: "line %d: not recognised (neither a comment, a [section] nor KEY = value)",
	ImpKeyFirst:     "line %d: key before any [section]",
	ImpBadKey:       "line %d: invalid key name %s",
	ImpDupKey:       "line %d: [%s] key %s appears twice (key names are case-insensitive)",
	ImpCommentGone:  "line %d: inline comment of secret key %s removed",
	ImpCaseMerged:   "line %d: [%s] %s in the store differ only in case; merged into %s",
	ImpRenamed:      "line %d: [%s] key %s renamed to %s",
	ImpFill:         "line %d: [%s] %s is still <fill>; fill it in",
	ImpDeleteNone:   "line %d: [%s] %s does not exist; <delete> ignored",
	ImpHoldAmbig:    "line %d: [%s] %s is <hold>, but %s in the store differ only in case, so the old value is ambiguous; give a new value",
	ImpHoldNone:     "line %d: [%s] %s is <hold>, but the store has no old value",
	ImpValueErr:     "line %d: [%s] %s: %s",
	ImpStoreClash:   "[%s] %s in the store differ only in case (they would clash on injection); write one of them in the import file",
	ImpSectionKept:  "[%s] is not in the import file; kept as it is (descriptions included)",
	ImpKeysKept:     "[%s] %s not in the import file; old values kept",
	ImpKeyErr:       "[%s] %s: %s",
	ImpFailed:       "import of %s failed; nothing written:",
	ItemBad:         "  ✗ %s",
	ItemNote:        "  · %s",
	ImpSelfCheck:    "self-check failed; nothing written: %s",
	ImpCaseClash:    "[%s] %s and %s %s differ only in case (they would clash on injection)",
	ImpBothQuotes:   "the value cannot be stored unchanged in an INI line (it holds a line break, both quote characters, or U+2028 / U+2029 that would need quoting); nothing written",
	ImpDoneBackup:   "imported %s (previous file saved as %s)",
	ImpDoneNew:      "imported %s (new file)",
	ImpFileDeleted:  "; import file deleted",
	RepLine:         "  [%s] %s",
	RepAdded:        "added %s",
	RepUpdated:      "updated %s",
	RepDeleted:      "deleted %s",
	RepNone:         "no change",
	RepSep:          "; ",
	ImpShredLeft:    "import file not shredded (%s; the next management command retries)",
	ImpShredErr:     "import file not shredded: %s",
	Committed:       "!!! the import is written to the store (committed, exit code %d), but these follow-up steps are not complete:",
	PendingItem:     "!!!   %s",
	CommittedHint:   "!!! after fixing it, run with-secrets --backup (if the backup directory is unusable: with-secrets --backup <new dir>)",

	BackupKeyGone:      "the backup key was moved away while waiting (a restore or undo may have just run); run the command again",
	BackupConfUsing:    "%s; using %s instead",
	BackupDone:         "backed up (%s): %s",
	BackupPassNotSaved: "new passphrase not saved (automatic backups still use the old one; %s uses the new one): %s",
	BackupDirNotSaved:  "backup directory setting not saved (automatic backups still go to %s): %s",
	BackupIncomplete:   "!!! the bundle is written, but the settings were not fully saved (exit code %d):",
	BackupRetryHint:    "!!! after fixing it, run the same with-secrets --backup command again",
	BackupAutoDir:      "automatic backup directory: %s (a backup after every --import; the newest %d are kept, plus the base)",

	MissingBundle:   "missing backup bundle path",
	VerifyBundle:    "bundle: %s (%s, %s)",
	VerifyCounts:    "  %d file(s), %d node(s), %d encrypted value(s) checked one by one",
	VerifyOK:        "  ✓ passphrase correct, content complete, usable for restore",
	PayloadBadName:  "invalid file name %s",
	PayloadNoKey:    "%s [%s] %s: encrypted, but the bundle has no data key",
	PayloadNoDecr:   "%s [%s] %s: does not decrypt",
	RestoreCheck:    "bundle check failed; nothing restored",
	RestoreKeyDiff:  "the staged data key does not match",
	RestoreBkBad:    "the staged backup key does not unwrap",
	RestoreNotStart: "restore not started; the existing store is unchanged: %s",
	RestoreAside:    "existing files moved to %s (undo: with-secrets --undo-restore)",
	RestoreDone:     "restored %d file(s), %d node(s) (%s backup of %s)",
	RestoreRebound:  "data key re-bound to this machine and user; automatic backups keep the same passphrase, directory: %s",
	UndoNone:        "there is no restore to undo",
	UndoDone:        "restore undone: put back %d file(s) from %s; the restored files were moved to %s",

	TestCredBad:  "not a testfile credential",
	TestCredName: "credential name mismatch",
}

func init() {
	for id, text := range adminTable {
		if _, dup := table[id]; dup {
			panic("msg: duplicate id " + string(id))
		}
		table[id] = text
	}
}
