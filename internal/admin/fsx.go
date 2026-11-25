package admin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/VanePulse/GSeal/internal/fault"
	"github.com/VanePulse/GSeal/internal/keys"
	"github.com/VanePulse/GSeal/internal/msg"
)

// ensureDir creates d (and parents) with mode 700.
func ensureDir(d string) error { return os.MkdirAll(d, 0o700) }

// exists reports whether p exists (without following a final symlink).
func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// writeAll writes all of b at the current offset. The short-write fault
// writes half and fails.
func writeAll(f *os.File, b []byte, faultable bool) error {
	if faultable && fault.Is("short-write") {
		f.Write(b[:len(b)/2])
		return msg.Errorf(msg.ShortWriteIn)
	}
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = msg.Errorf(msg.ShortWrite)
	}
	return err
}

// fsyncDir makes a rename / unlink in dir durable (best effort).
func fsyncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

func tmpName(path string) string {
	b := make([]byte, 3)
	rand.Read(b)
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(b))
}

// publish moves a finished temp file into place. exclusive refuses an
// existing target (link fails with EEXIST) instead of replacing it. The
// rename / link is the last step that can fail, so a caller that gets an
// error knows path was not replaced.
func publish(tmp, path string, exclusive bool) error {
	err := os.Chmod(tmp, 0o600)
	if err == nil {
		if exclusive {
			err = os.Link(tmp, path)
		} else {
			err = os.Rename(tmp, path)
		}
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if exclusive {
		os.Remove(tmp)
	}
	fsyncDir(filepath.Dir(path))
	return nil
}

// atomicWrite: temp file, full write, fsync, rename (or link): readers and a
// crash only ever see the complete old or the complete new content.
func atomicWrite(path string, data []byte, exclusive bool) error {
	tmp := tmpName(path)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := writeAll(f, data, true); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return publish(tmp, path, exclusive)
}

// wrapTo wraps secret with the key backend into a temp file and publishes it.
func (a *Admin) wrapTo(b keys.Backend, name string, secret []byte, path string, exclusive bool) error {
	tmp := tmpName(path)
	err := fault.At("wrap")
	if err == nil {
		err = b.Wrap(name, secret, tmp)
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err == nil {
		var f *os.File
		if f, err = os.Open(tmp); err == nil {
			err = f.Sync()
			f.Close()
		}
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return publish(tmp, path, exclusive)
}

const shredding = ".shredding"

// shred overwrites a regular file with zeros, then unlinks it. It is first
// renamed to <name>.shredding, so an interruption never leaves a damaged
// file under the import name. It returns true when the file is gone; false
// when it was kept (not a regular file, or the overwrite failed: retried by
// the next management command).
func (a *Admin) shred(path string) (bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !st.Mode().IsRegular() {
		a.warn(msg.Text(msg.ShredSkip, path))
		return false, nil
	}
	doomed := path
	if !strings.HasSuffix(path, shredding) {
		doomed = path + shredding
		if err := os.Rename(path, doomed); err != nil {
			return false, err
		}
	}
	if err := overwrite(doomed); err != nil {
		a.warn(msg.Text(msg.ShredFailed, doomed, err.Error()))
		return false, nil
	}
	if err := os.Remove(doomed); err != nil {
		return false, err
	}
	fsyncDir(filepath.Dir(doomed))
	return true, nil
}

func overwrite(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	zeros := make([]byte, 1<<16)
	for pos := int64(0); pos < st.Size(); pos += int64(len(zeros)) {
		n := min(int64(len(zeros)), st.Size()-pos)
		if _, err := f.WriteAt(zeros[:n], pos); err != nil {
			return err
		}
	}
	if err := fault.At("shred-overwrite"); err != nil {
		return err
	}
	return f.Sync()
}

// sweepShredding finishes shredding left behind by an interrupted import
// (such a file may still hold plaintext).
func (a *Admin) sweepShredding() {
	ents, err := os.ReadDir(a.importDir())
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), shredding) {
			continue
		}
		gone, err := a.shred(filepath.Join(a.importDir(), e.Name()))
		switch {
		case err != nil:
			a.warn(msg.Text(msg.SweepFailed, e.Name(), err.Error()))
		case gone:
			a.warn(msg.Text(msg.SweepDone, e.Name()))
		}
	}
}

// localBackup copies path to env/.backup/<label>.<stamp>; "" if path is absent.
func (a *Admin) localBackup(path, label string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := ensureDir(a.localBackupDir()); err != nil {
		return "", err
	}
	dst := filepath.Join(a.localBackupDir(), label+"."+stamp())
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		return "", err
	}
	return dst, os.Chmod(dst, 0o600)
}
