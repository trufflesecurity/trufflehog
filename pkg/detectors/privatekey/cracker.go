package privatekey

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"errors"

	"golang.org/x/crypto/ssh"
)

//go:embed "list.txt"
var rawCrackList []byte
var passphrases [][]byte

func init() {
	passphrases = bytes.Split(rawCrackList, []byte("\n"))
}

var (
	ErrUncrackable = errors.New("unable to crack encryption")
)

// crackFailedErrorField is the fixed value logged in the error field when a
// crack attempt fails outright. The underlying error's text can embed
// input-derived material (ssh's unsupported-key-type error includes the PEM
// block type), so the log carries this classifier instead, and the full
// error already rides the finding's verification error.
const crackFailedErrorField = "key parse error (detail on the finding's verification error)"

// crackResult reports a wordlist walk: how many passphrases were tried,
// and the parsed key plus recovered passphrase when one succeeded. key and
// passphrase are set only when the accompanying error is nil; attempts is
// valid on every return.
type crackResult struct {
	key        any
	passphrase string
	attempts   int
}

// Crack attempts to decrypt an encrypted private key by trying each
// passphrase in the built-in wordlist, returning the parsed key and the
// recovered passphrase on success. This signature is public API and stays
// stable; the wordlist walk behavior is unchanged.
func Crack(in []byte) (any, string, error) {
	res, err := crack(context.Background(), in)
	return res.key, res.passphrase, err
}

// crack walks the built-in wordlist against an encrypted key, returning
// the walk result (attempt count always; the parsed key and recovered
// passphrase on success) and the error that stopped it: ErrUncrackable
// when the list was exhausted, the parse failure that prevented further
// attempts, or the context error that stopped the walk early.
//
// A done context stops the walk between attempts; a single attempt is
// uninterruptible because its cost is chosen by the key's author.
func crack(ctx context.Context, in []byte) (crackResult, error) {
	attempts := 0
	for _, passphrase := range passphrases {
		if err := ctx.Err(); err != nil {
			return crackResult{attempts: attempts}, err
		}
		attempts++
		parsed, err := ssh.ParseRawPrivateKeyWithPassphrase(in, passphrase)
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				continue
			}
			return crackResult{attempts: attempts}, err
		}
		return crackResult{key: parsed, passphrase: string(passphrase), attempts: attempts}, nil
	}
	return crackResult{attempts: attempts}, ErrUncrackable
}

// Outcome values for the crack log line's outcome field.
const (
	crackOutcomeCracked     = "cracked"
	crackOutcomeUncrackable = "uncrackable"
	crackOutcomeFailed      = "failed"
	crackOutcomeAborted     = "aborted"
)

// crackOutcome classifies a crack result for logging: "cracked" when a
// passphrase was recovered, "uncrackable" when the wordlist was exhausted
// without one, "failed" when the key could not be attempted at all, and
// "aborted" when the walk was stopped by its context before either end.
func crackOutcome(err error) string {
	switch {
	case err == nil:
		return crackOutcomeCracked
	case errors.Is(err, ErrUncrackable):
		return crackOutcomeUncrackable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return crackOutcomeAborted
	default:
		return crackOutcomeFailed
	}
}
