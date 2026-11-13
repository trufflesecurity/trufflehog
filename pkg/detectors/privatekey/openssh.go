package privatekey

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
)

// opensshMagic starts the decoded body of every key in the OpenSSH private
// key format.
var opensshMagic = []byte("openssh-key-v1\x00")

// opensshBcryptRounds reads the bcrypt round count from an OpenSSH key's
// header. The decoded key stores the cipher name, KDF name, and KDF options
// before the encrypted section, so the round count is readable without the
// passphrase. Keys in any other format (plain PEM, or OpenSSH keys whose KDF
// is not bcrypt) return ok=false so the caller treats them as before.
func opensshBcryptRounds(key []byte) (rounds uint32, ok bool) {
	block, _ := pem.Decode(key)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" || !bytes.HasPrefix(block.Bytes, opensshMagic) {
		return 0, false
	}
	r := bytes.NewReader(block.Bytes[len(opensshMagic):])
	// The cipher name is irrelevant to the KDF round count.
	if _, err := readSSHString(r); err != nil {
		return 0, false
	}
	kdfName, err := readSSHString(r)
	if err != nil {
		return 0, false
	}
	if string(kdfName) != "bcrypt" {
		return 0, false
	}
	// KDF options for bcrypt are the salt followed by the round count; the
	// count is the last four bytes of the options blob.
	opts, err := readSSHString(r)
	if err != nil {
		return 0, false
	}
	if len(opts) < 4 {
		return 0, false
	}
	rounds = binary.BigEndian.Uint32(opts[len(opts)-4:])
	return rounds, true
}

// readSSHString reads one length-prefixed string from an SSH wire buffer.
func readSSHString(r *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	// Cap the read at what the key actually holds, so a corrupt or hostile
	// length cannot make the parser allocate gigabytes.
	if int64(n) > int64(r.Len()) {
		return nil, errors.New("string length exceeds remaining key data")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
