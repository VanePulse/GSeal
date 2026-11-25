// Command with-secrets injects credentials from a local encrypted store into
// a child process and redacts them from its output.
package main

import (
	"os"

	"github.com/VanePulse/GSeal/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
