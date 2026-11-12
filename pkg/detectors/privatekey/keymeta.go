package privatekey

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
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
		"none":                          {},
	}
	knownKDFs = map[string]struct{}{
		"bcrypt": {},
		"none":   {},
	}
)

// opensshMagic prefixes the binary payload of every "OPENSSH PRIVATE KEY"
// PEM block, NUL-terminated.
var opensshMagic = []byte("openssh-key-v1\x00")

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
// salt bytes inside the KDF options are validated for length and skipped.
//
// The OpenSSH container stores the cipher name, KDF name, and KDF options
// as length-prefixed fields after the "openssh-key-v1\0" magic, and those
// lengths are attacker-controlled, so every read is bounds-checked and any
// truncation or unexpected shape reports format "unknown" rather than
// erroring. A key in any other PEM private-key format (such as a
// traditional RSA block) reports format "pem" with no cipher, KDF, or
// round information, because the legacy header does not carry them.
func parseKeyMetadata(key []byte) keyMetadata {
	block, _ := pem.Decode(key)
	if block == nil {
		return keyMetadata{format: formatUnknown}
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		return keyMetadata{format: formatPEM}
	}
	return parseOpenSSHHeader(block.Bytes)
}

// parseOpenSSHHeader walks the cleartext OpenSSH header: the magic, then
// length-prefixed ciphername, kdfname, and kdfoptions strings, then the
// kdfoptions payload (a uint32 salt length, the salt bytes, and a uint32
// round count).
func parseOpenSSHHeader(b []byte) keyMetadata {
	if len(b) < len(opensshMagic) || !bytes.Equal(b[:len(opensshMagic)], opensshMagic) {
		return keyMetadata{format: formatUnknown}
	}
	b = b[len(opensshMagic):]

	cipherName, b, ok := readLengthPrefixed(b)
	if !ok {
		return keyMetadata{format: formatUnknown}
	}
	kdfName, b, ok := readLengthPrefixed(b)
	if !ok {
		return keyMetadata{format: formatUnknown}
	}
	// The remainder holds the public key and the encrypted private block;
	// the header walk stops at the KDF options.
	kdfOptions, _, ok := readLengthPrefixed(b)
	if !ok {
		return keyMetadata{format: formatUnknown}
	}

	meta := keyMetadata{
		format: formatOpenSSH,
		cipher: boundHeaderField(cipherName, knownCiphers),
		kdf:    boundHeaderField(kdfName, knownKDFs),
	}
	switch kdfName {
	case "none":
		// Unencrypted key: no KDF options to walk, rounds stay 0.
		return meta
	case "bcrypt":
		// Only bcrypt has a defined options shape. Any other KDF name
		// leaves the round count unset rather than misparsed.
		rounds, ok := readKDFOptions([]byte(kdfOptions))
		if !ok {
			return keyMetadata{format: formatUnknown}
		}
		meta.kdfRounds = rounds
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

// readLengthPrefixed reads one uint32-prefixed string field and returns the
// unread remainder. The declared length is attacker-controlled and can be
// as large as 0xFFFFFFFF, so it is compared in uint64 space: an int-based
// check could overflow before the slice bounds are consulted.
func readLengthPrefixed(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

// readKDFOptions parses the bcrypt KDF parameter block: a uint32 salt
// length, the salt bytes themselves (validated for length, never
// returned), and a uint32 round count.
func readKDFOptions(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	saltLen := binary.BigEndian.Uint32(b)
	if uint64(saltLen) > uint64(len(b)-4) {
		return 0, false
	}
	rest := b[4+saltLen:]
	if len(rest) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(rest), true
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
