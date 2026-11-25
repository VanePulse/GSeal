// Package tty reads secrets from the controlling terminal (/dev/tty) in raw
// mode, without echo. A secret is never taken from arguments or environment
// variables.
package tty

import (
	"os"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/VanePulse/GSeal/internal/msg"
)

// Secrets shows each prompt in turn and returns the answers. Input is read
// one byte at a time, so input typed ahead for a later prompt (even one asked
// by a later call) is left in the terminal for it.
//
// Keys: Enter or Ctrl-D ends an answer, Backspace deletes, Ctrl-C cancels,
// other control characters are ignored. Raw mode turns off output
// processing, so line ends are written as CR LF.
func Secrets(prompts ...string) ([]string, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, msg.Errorf(msg.PromptNoTTY)
	}
	defer f.Close()
	fd := int(f.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, msg.Errorf(msg.PromptNoTTY)
	}
	defer term.Restore(fd, old)

	var answers []string
	var cur []rune
	var pending []byte
	f.WriteString(prompts[0])
	b := make([]byte, 1)
	for {
		n, err := f.Read(b)
		if n == 0 {
			if err != nil {
				f.WriteString("\r\n")
				return nil, msg.Errorf(msg.PromptCancelled)
			}
			continue
		}
		pending = append(pending, b[0])
		if !utf8.FullRune(pending) {
			continue
		}
		r, _ := utf8.DecodeRune(pending) // invalid bytes become U+FFFD
		pending = pending[:0]
		switch {
		case r == 0x03: // Ctrl-C
			f.WriteString("\r\n")
			return nil, msg.Errorf(msg.PromptCancelled)
		case r == '\r' || r == '\n' || r == 0x04:
			f.WriteString("\r\n")
			answers = append(answers, string(cur))
			cur = nil
			if len(answers) == len(prompts) {
				return answers, nil
			}
			f.WriteString(prompts[len(answers)])
		case r == 0x7f || r == '\b':
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
		case r >= ' ':
			cur = append(cur, r)
		}
	}
}

// MinPass is the minimum passphrase length (characters).
const MinPass = 12

// NewPassphrase asks for a new passphrase twice (first, again) and checks it.
func NewPassphrase(first, again msg.ID) (string, error) {
	ans, err := Secrets(msg.Text(first), msg.Text(again))
	if err != nil {
		return "", err
	}
	if ans[0] != ans[1] {
		return "", msg.Errorf(msg.PassMismatch)
	}
	if utf8.RuneCountInString(ans[0]) < MinPass {
		return "", msg.Errorf(msg.PassShort, MinPass)
	}
	return ans[0], nil
}
