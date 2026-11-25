package privatekey

import (
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// Key format values reported by parseKeyMetadata. The format decides how
// much of the header is readable: only the OpenSSH container stores the
// cipher, KDF, and KDF round count in the clear. "unknown" is the failure
// signal: parseKeyMetadata never errors, and any truncation or unexpected
// shape reports it.
const (
	formatOpenSSH = "openssh"
	formatPEM     = "pem"
	formatUnknown = "unknown"
)

// KDF round-count bucket boundaries for the kdf_rounds label. Estimated
// against a 10s detection timeout from a local benchmark: 16 rounds (the
// OpenSSH default) walks the wordlist in about 24s, so a default-cost key
// already overruns the timeout. Worth re-checking if the timeout or the
// benchmark changes.
const (
	kdfRoundsBucketLow  = 16
	kdfRoundsBucketHigh = 256
)

// Header field values that appear in log output. The cipher and KDF name
// are attacker-controlled strings, so only known OpenSSH values survive
// into a log line and anything else collapses to "other"; the length cap is
// a backstop in case the known set ever grows past it.
const (
	maxHeaderFieldValueLen = 64
	otherHeaderValue       = "other"
)

// Block type and KDF names this file's checks, maps, and switch share.
// openssh.go compares the same block type and KDF names; keep the
// spellings consistent across the package.
const (
	blockTypeOpenSSHPrivateKey = "OPENSSH PRIVATE KEY"
	kdfNameNone                = "none"
	kdfNameBcrypt              = "bcrypt"
)

// knownCiphers and knownKDFs are the value sets the OpenSSH container
// defines for its ciphername and kdfname header fields. The CBC ciphers
// belong there too: aes256-cbc was ssh-keygen's default for new-format
// keys before the switch to aes256-ctr, and the CBC family remains
// accepted for private-key encryption, so legacy keys legitimately carry
// those values - without them, real ciphers would collapse to "other"
// alongside unrecognized attacker-controlled names.
var (
	knownCiphers = map[string]struct{}{
		"3des-cbc":                      {},
		"aes128-cbc":                    {},
		"aes128-ctr":                    {},
		"aes128-gcm@openssh.com":        {},
		"aes192-cbc":                    {},
		"aes192-ctr":                    {},
		"aes256-cbc":                    {},
		"aes256-ctr":                    {},
		"aes256-gcm@openssh.com":        {},
		"chacha20-poly1305@openssh.com": {},
		kdfNameNone:                     {},
	}
	knownKDFs = map[string]struct{}{
		kdfNameBcrypt: {},
		kdfNameNone:   {},
	}
)

// keyMetadata carries the non-secret header fields of a private key that
// determine how expensive each passphrase attempt is: the cipher a
// successful guess must decrypt with, and the KDF and its round count,
// which the key's author chose. It never holds key material; the OpenSSH
// format stores these fields in the clear ahead of the encrypted blob, and
// only the cleartext is read. cipher and kdf are bounded to the known
// OpenSSH value sets because they flow into log output.
type keyMetadata struct {
	format    string // "openssh", "pem", or "unknown"
	cipher    string // e.g. "aes256-ctr"; empty for legacy PEM; "other" if unrecognized
	kdf       string // e.g. "bcrypt"; empty for legacy PEM; "other" if unrecognized
	kdfRounds uint32 // 0 when format is not openssh
}

// parseKeyMetadata reads non-secret header fields from a PEM-encoded
// private key without decrypting it. It never returns key material: the
// salt inside the KDF options is parsed and dropped, never stored.
//
// The OpenSSH container stores the cipher name, KDF name, and KDF options
// after the "openssh-key-v1\0" magic. The header is read with a
// prefix-only mirror of the cap check's wire structs (openssh.go):
// kdfOpts is the shared struct, so the round count here matches the cap
// check's whenever both parses succeed. The prefix deliberately parses
// where the cap check's full-struct parse bails, so attribution survives
// a key truncated right after its options; keep the two mirror structs
// field-compatible. Any truncation or unexpected shape reports format
// "unknown" rather than erroring. A key in any other PEM private-key
// format (such as a traditional RSA block) reports format "pem" with no
// cipher, KDF, or round information, because the legacy header does not
// carry them.
func parseKeyMetadata(key []byte) keyMetadata {
	block, _ := pem.Decode(key)
	if block == nil {
		return keyMetadata{format: formatUnknown}
	}
	if block.Type != blockTypeOpenSSHPrivateKey {
		return keyMetadata{format: formatPEM}
	}
	return parseOpenSSHHeader(block.Bytes)
}

// openSSHHeaderPrefix is the cleartext front of an OpenSSH key body: the
// three header strings. Everything after them (key count, public key,
// encrypted block) lands in Rest unread - metadata reads only the header,
// so a key truncated right after its options still reports its format,
// cipher, and KDF.
type openSSHHeaderPrefix struct {
	CipherName string
	KdfName    string
	KdfOpts    string
	Rest       []byte `ssh:"rest"`
}

// parseOpenSSHHeader reads the cleartext OpenSSH header: the magic, then
// the length-prefixed ciphername, kdfname, and kdfoptions strings, then
// the kdfoptions payload (a salt blob and a uint32 round count).
func parseOpenSSHHeader(b []byte) keyMetadata {
	if len(b) < len(privateKeyAuthMagic) || string(b[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return keyMetadata{format: formatUnknown}
	}
	var w openSSHHeaderPrefix
	if err := ssh.Unmarshal(b[len(privateKeyAuthMagic):], &w); err != nil {
		return keyMetadata{format: formatUnknown}
	}

	meta := keyMetadata{
		format: formatOpenSSH,
		cipher: boundHeaderField(w.CipherName, knownCiphers),
		kdf:    boundHeaderField(w.KdfName, knownKDFs),
	}
	switch w.KdfName {
	case kdfNameNone:
		// Unencrypted key: no KDF options to walk, rounds stay 0.
		return meta
	case kdfNameBcrypt:
		// Only bcrypt has a defined options shape. A blob that does not
		// parse leaves the round count unset rather than misparsed, while
		// the format, cipher, and KDF attribution survive: the cap check
		// refuses this key as too expensive, and the log should say what
		// kind of key it refused.
		var opts kdfOpts
		if err := ssh.Unmarshal([]byte(w.KdfOpts), &opts); err != nil {
			return meta
		}
		meta.kdfRounds = opts.Rounds
	}
	return meta
}

// boundHeaderField maps an attacker-controlled header string onto a value
// safe to put in log output: known values pass through, anything else
// collapses to "other".
func boundHeaderField(value string, known map[string]struct{}) string {
	if _, ok := known[value]; ok && len(value) <= maxHeaderFieldValueLen {
		return value
	}
	return otherHeaderValue
}

// kdfRoundsLabel maps the KDF round count to a bounded metric label value.
// Raw counts never become labels: they are attacker-controlled uint32
// header values, so they collapse into a few buckets, with "unknown" for
// non-OpenSSH keys and unparseable counts.
func (m keyMetadata) kdfRoundsLabel() string {
	if m.format != formatOpenSSH || m.kdfRounds == 0 {
		return "unknown"
	}
	switch {
	case m.kdfRounds <= kdfRoundsBucketLow:
		return "<=16"
	case m.kdfRounds <= kdfRoundsBucketHigh:
		return "<=256"
	default:
		return ">256"
	}
}
