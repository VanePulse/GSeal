package admin

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/VanePulse/GSeal/internal/fault"
	"github.com/VanePulse/GSeal/internal/msg"
)

// The management lock is a kernel flock(2) on env/.lock. The kernel releases
// it when the process ends however it ends, so there is no stale lock to break
// and no takeover race. The file content (holder pid / command) is only
// informational; it is cleared on a normal release, so content found when
// acquiring means the previous holder did not finish.

type lockInfo struct {
	PID     int    `json:"pid"`
	Cmd     string `json:"cmd"`
	Started string `json:"started"`
}

func (a *Admin) readLock() *lockInfo {
	b, err := os.ReadFile(a.lockFile())
	if err != nil || len(b) == 0 {
		return nil
	}
	var l lockInfo
	if json.Unmarshal(b, &l) != nil {
		return nil
	}
	return &l
}

func holder(l *lockInfo) (cmd, pid string) {
	if l == nil {
		return "?", "?"
	}
	return l.Cmd, strconv.Itoa(l.PID)
}

// lockWait is how long a command waits for the lock (GSEAL_LOCK_WAIT_MS,
// default 30 s).
func lockWait() time.Duration {
	if ms, err := strconv.Atoi(os.Getenv("GSEAL_LOCK_WAIT_MS")); err == nil && ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return 30 * time.Second
}

func (a *Admin) acquireLock(cmd string) error {
	if err := ensureDir(a.St.Env); err != nil {
		return err
	}
	f, err := os.OpenFile(a.lockFile(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return msg.Errorf(msg.LockFailed, a.lockFile(), err.Error())
	}
	fd := int(f.Fd())
	err = flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		c, p := holder(a.readLock())
		a.warn(msg.Text(msg.LockWaiting, c, p))
		deadline := time.Now().Add(lockWait())
		for errors.Is(err, unix.EWOULDBLOCK) && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
			err = flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		}
		if errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			c, p := holder(a.readLock())
			return msg.Errorf(msg.LockBusy, c, p)
		}
	}
	if err != nil {
		f.Close()
		return msg.Errorf(msg.LockFailed, a.lockFile(), err.Error())
	}
	a.lock = f
	if prev := a.readLock(); prev != nil {
		c, p := holder(prev)
		a.warn(msg.Text(msg.LockStale, c, p, prev.Started))
	}
	info, _ := json.Marshal(lockInfo{os.Getpid(), cmd, isoNow()})
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(info, 0); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := fault.At("after-lock"); err != nil {
		return err
	}
	fault.Hold()
	return a.recover()
}

func flock(fd, how int) error {
	for {
		err := unix.Flock(fd, how)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func (a *Admin) releaseLock() {
	if a.lock == nil {
		return
	}
	a.lock.Truncate(0)
	a.lock.Close() // drops the flock
	a.lock = nil
}

// recover runs under the lock before any command: it finishes what an
// interrupted one left.
func (a *Admin) recover() error {
	b, err := os.ReadFile(a.journalFile())
	if err == nil {
		var j journal
		err = json.Unmarshal(b, &j)
		if err == nil {
			if err = a.runSwap(&j); err == nil {
				err = a.finishSwap(&j)
			}
		}
		if err != nil {
			return swapPending{msg.Errorf(msg.RecoverFailed, opName(j.Op), err.Error(), a.journalFile())}
		}
		a.warn(msg.Text(msg.RecoverDone, opName(j.Op), j.TS))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return swapPending{msg.Errorf(msg.RecoverFailed, "?", err.Error(), a.journalFile())}
	}
	a.sweepShredding()
	return nil
}
