//go:build !gsealtest

package keys

// Default returns the key backend for new keys: systemd-creds.
func Default() Backend { return SystemdCreds{} }

func detectTest(string) (Backend, bool) { return nil, false }

func byNameTest(string) (Backend, bool) { return nil, false }
