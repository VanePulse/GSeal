package admin

import (
	"github.com/VanePulse/GSeal/internal/msg"
	"github.com/VanePulse/GSeal/internal/tty"
)

func promptSecrets(prompts ...string) ([]string, error) { return tty.Secrets(prompts...) }

func askNewPassphrase() (string, error) { return tty.NewPassphrase(msg.PromptNew, msg.PromptAgain) }
