//go:build !gsealtest

package fault

// Enabled reports whether this build contains the injection points.
const Enabled = false

// At does nothing in a release build.
func At(string) error { return nil }

// Is is always false in a release build.
func Is(string) bool { return false }

// Hold does nothing in a release build.
func Hold() {}
