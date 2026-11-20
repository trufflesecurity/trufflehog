package privatekey

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"

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
	// ErrKDFTooExpensive is returned without attempting any passphrase when a
	// key's KDF is more expensive than the crack budget allows.
	ErrKDFTooExpensive = errors.New("key KDF is too expensive to crack")
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

// maxCrackRounds caps the bcrypt KDF round count this detector will attempt
// to crack. The round count is chosen by whoever created the key and the KDF
// cost is linear in rounds; OpenSSH's default is 16. 256 is 16x that default:
// a single wrong guess on a key at the cap costs on the order of a second of
// CPU, so a wordlist crack is hopeless within any bounded budget. x/crypto
// refuses round counts above 2048 on its own; this lower cap keeps
// hardened-but-legal keys from making each attempt that expensive. Division
// of labor: the cap bounds what one attempt can cost, and the context check
// below bounds the total, where the caller sets a deadline at all.
const maxCrackRounds = 256

// Crack attempts to decrypt an encrypted private key by trying each
// passphrase in the built-in wordlist, returning the parsed key and the
// recovered passphrase on success. The caller's context stops the walk
// between attempts once it is done.
func Crack(ctx context.Context, in []byte) (any, string, error) {
	res, err := crack(ctx, in)
	return res.key, res.passphrase, err
}

// crack walks the built-in wordlist against an encrypted key, returning
// the walk result (attempt count always; the parsed key and recovered
// passphrase on success) and the error that stopped it: ErrKDFTooExpensive
// when the key's KDF exceeds maxCrackRounds, ErrUncrackable when the list
// was exhausted, the parse failure that prevented further attempts, or the
// wrapped context error that stopped the walk early.
//
// A done context stops the walk between attempts; a single attempt is
// uninterruptible because its cost is chosen by the key's author. The
// parse-failure return is deliberately bare: the finding's verification
// error unwraps to the last error in the chain, so a wrapper here would
// never reach it, and the log's outcome field classifies the failure
// without raw error text.
func crack(ctx context.Context, in []byte) (crackResult, error) {
	if rounds, ok := opensshBcryptRounds(in); ok && rounds > maxCrackRounds {
		return crackResult{}, fmt.Errorf("%w: %d rounds exceeds cap of %d", ErrKDFTooExpensive, rounds, maxCrackRounds)
	}
	attempts := 0
	for _, passphrase := range passphrases {
		// A wrong passphrase costs a full KDF run whose cost is set by the
		// key's author, so stop between attempts once the caller's context is
		// done. The in-flight attempt cannot be interrupted:
		// ssh.ParseRawPrivateKeyWithPassphrase takes no context.
		if err := ctx.Err(); err != nil {
			return crackResult{attempts: attempts}, fmt.Errorf("stopped cracking after %d of %d passphrase attempts: %w", attempts, len(passphrases), err)
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
	crackOutcomeCracked      = "cracked"
	crackOutcomeUncrackable  = "uncrackable"
	crackOutcomeFailed       = "failed"
	crackOutcomeTooExpensive = "too_expensive"
	crackOutcomeAborted      = "aborted"
)

// crackOutcome classifies a crack result for logging: "cracked" when a
// passphrase was recovered, "uncrackable" when the wordlist was exhausted
// without one, "failed" when a parse error ended the walk after one or
// more attempts, "too_expensive" when the KDF cap refused the key before
// any attempt, and "aborted" when the walk was stopped by its context
// before either end.
func crackOutcome(err error) string {
	switch {
	case err == nil:
		return crackOutcomeCracked
	case errors.Is(err, ErrUncrackable):
		return crackOutcomeUncrackable
	case errors.Is(err, ErrKDFTooExpensive):
		return crackOutcomeTooExpensive
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return crackOutcomeAborted
	default:
		return crackOutcomeFailed
	}
}
