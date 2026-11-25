package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/VanePulse/GSeal/internal/fault"
	"github.com/VanePulse/GSeal/internal/msg"
)

// Restore and undo replace the whole store in two phases recorded in a
// journal (env/.swap-journal.json, same format as VaneSecret):
//
//  1. move Out (names in env/) into OutDir
//  2. move In (names in InDir) into env/
//
// runSwap is idempotent, so after a crash it is simply run again (roll
// forward).
type journal struct {
	Op     string   `json:"op"`
	TS     string   `json:"ts"`
	From   string   `json:"from,omitempty"`
	Out    []string `json:"out"`
	OutDir string   `json:"outDir"`
	In     []string `json:"in"`
	InDir  string   `json:"inDir"`
}

const (
	opRestore = "restore"
	opUndo    = "undo-restore"
	opApply   = "apply-policy"
	opRotate  = "rotate-datakey"
)

func opName(op string) string {
	switch op {
	case opRestore:
		return msg.Text(msg.OpRestore)
	case opApply:
		return msg.Text(msg.OpApply)
	case opRotate:
		return msg.Text(msg.OpRotate)
	}
	return msg.Text(msg.OpUndo)
}

// swapPending: a restore / undo is half done; the next management command
// completes it (exit 5).
type swapPending struct{ err error }

func (s swapPending) Error() string { return s.err.Error() }

func (a *Admin) runSwap(j *journal) error {
	if err := ensureDir(j.OutDir); err != nil {
		return err
	}
	for _, f := range j.Out {
		src, dst := filepath.Join(a.St.Env, f), filepath.Join(j.OutDir, f)
		if exists(dst) || !exists(src) {
			continue // already moved
		}
		if err := fault.At("swap-out"); err != nil {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	for _, f := range j.In {
		src, dst := filepath.Join(j.InDir, f), filepath.Join(a.St.Env, f)
		if !exists(src) {
			continue // already moved
		}
		if err := fault.At("swap-in"); err != nil {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	fsyncDir(a.St.Env)
	return nil
}

// undoSwap puts things back after a failed (not crashed) swap.
func (a *Admin) undoSwap(j *journal) error {
	for _, f := range j.In {
		cur, back := filepath.Join(a.St.Env, f), filepath.Join(j.InDir, f)
		if !exists(back) && exists(cur) {
			if err := os.Rename(cur, back); err != nil {
				return err
			}
		}
	}
	for _, f := range j.Out {
		aside, cur := filepath.Join(j.OutDir, f), filepath.Join(a.St.Env, f)
		if exists(aside) && !exists(cur) {
			if err := os.Rename(aside, cur); err != nil {
				return err
			}
		}
	}
	fsyncDir(a.St.Env)
	return nil
}

type restoreRecord struct {
	TS        string   `json:"ts"`
	Installed []string `json:"installed"`
	From      string   `json:"from"`
}

func (a *Admin) finishSwap(j *journal) error {
	if err := fault.At("finish-swap"); err != nil {
		return err
	}
	switch j.Op {
	case opRestore:
		if err := atomicWrite(filepath.Join(j.OutDir, "restore.json"), jsonIndent(restoreRecord{j.TS, j.In, j.From}), false); err != nil {
			return err
		}
		if err := os.RemoveAll(j.InDir); err != nil {
			return err
		}
	case opApply, opRotate:
		if err := os.RemoveAll(j.InDir); err != nil {
			return err
		}
	case opUndo:
		if exists(j.InDir) {
			if err := os.Rename(j.InDir, j.InDir+".undone"); err != nil {
				return err
			}
		}
	}
	// The journal going away is what ends the transaction; failing to remove
	// it is a failure (exit 5), and recover keeps refusing other work until
	// it is gone.
	if err := fault.At("journal-unlink"); err != nil {
		return err
	}
	if err := os.Remove(a.journalFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	fsyncDir(a.St.Env)
	return nil
}

func (a *Admin) commitSwap(j *journal) error {
	if err := atomicWrite(a.journalFile(), jsonIndent(j), false); err != nil {
		return err
	}
	if err := a.runSwap(j); err != nil {
		e2 := a.undoSwap(j)
		if e2 == nil {
			e2 = os.Remove(a.journalFile())
		}
		if e2 != nil {
			return swapPending{msg.Errorf(msg.SwapStuck, err.Error(), e2.Error())}
		}
		// Rolled back: drop what this attempt created (staged files, empty aside dir).
		if j.Op != opUndo {
			os.RemoveAll(j.InDir)
		}
		if ents, e := os.ReadDir(j.OutDir); e == nil && len(ents) == 0 {
			os.Remove(j.OutDir)
		}
		return msg.Errorf(msg.SwapRolledBack, err.Error())
	}
	// The files are swapped from here on: a bookkeeping failure must not read
	// as "unchanged". The journal stays, and the next command finishes it.
	if err := a.finishSwap(j); err != nil {
		return swapPending{msg.Errorf(msg.SwapFinishFailed, err.Error())}
	}
	return nil
}

// jsonIndent is JSON.stringify(v, null, 2) + "\n".
func jsonIndent(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	e.Encode(v)
	return b.Bytes()
}
