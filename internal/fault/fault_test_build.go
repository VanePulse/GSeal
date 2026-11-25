//go:build gsealtest

// Package fault holds the fault-injection points used by the test suite.
// They exist only in builds with the gsealtest tag; release builds compile
// the no-op version (fault_release.go), so GSEAL_FAULT / GSEAL_CRASH have no
// effect there.
//
//	GSEAL_FAULT=<point>   that step fails with an error
//	GSEAL_CRASH=<point>   the process is killed there (like a power cut)
//	GSEAL_HOLD_MS=<ms>    hold the management lock that long after taking it
package fault

import (
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/VanePulse/GSeal/internal/msg"
)

// Enabled reports whether this build contains the injection points.
const Enabled = true

// At is an injection point: it may kill the process or return an error.
func At(point string) error {
	if os.Getenv("GSEAL_CRASH") == point {
		syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(5 * time.Second)
	}
	if os.Getenv("GSEAL_FAULT") == point {
		return msg.Errorf(msg.FaultAt, point)
	}
	return nil
}

// Is reports whether GSEAL_FAULT names point (for faults that are not a
// plain error, such as a short write).
func Is(point string) bool { return os.Getenv("GSEAL_FAULT") == point }

// Hold sleeps for GSEAL_HOLD_MS milliseconds.
func Hold() {
	if ms, err := strconv.Atoi(os.Getenv("GSEAL_HOLD_MS")); err == nil && ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}
