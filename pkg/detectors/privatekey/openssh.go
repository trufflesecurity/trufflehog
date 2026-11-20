package privatekey

import (
	"encoding/pem"
	"math"

	"golang.org/x/crypto/ssh"
)

// privateKeyAuthMagic starts the decoded body of every key in the OpenSSH
// private key format (see PROTOCOL.key in the OpenSSH source distribution).
const privateKeyAuthMagic = "openssh-key-v1\x00"

// openSSHEncryptedPrivateKey and kdfOpts mirror the wire structs x/crypto
// parses the same bytes with in ssh/keys.go, so the round count read here is
// the round count the KDF will actually run at. Keep them in sync with
// x/crypto's private structs: if the parses ever diverge, the count read
// here silently stops matching the KDF's cost and keys are over- or
// under-refused. x/crypto exports no way to read the KDF options, so the
// header is read in the detector.
type openSSHEncryptedPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
	// Rest swallows trailing bytes the way x/crypto's copy of this struct
	// does. Without the tag, a key with bytes after PrivKeyBlock would fail
	// to parse here, read as ok=false, and skip the cap check that
	// x/crypto would still apply.
	Rest []byte `ssh:"rest"`
}

// kdfOpts deliberately has no ssh:"rest" field: that is what makes
// ssh.Unmarshal reject options blobs carrying trailing bytes, which is the
// fail-closed path below. Adding one for forward compatibility would
// silently disarm it.
type kdfOpts struct {
	Salt   string
	Rounds uint32
}

// opensshBcryptRounds reads the bcrypt round count from an OpenSSH key's
// header. The decoded key stores the cipher name, KDF name, and KDF options
// before the encrypted section, so the round count is readable without the
// passphrase; Crack uses it to refuse keys whose KDF exceeds maxCrackRounds
// before spending any passphrase attempt.
//
// ok=false means the key is not an OpenSSH bcrypt key, and it should be
// cracked exactly as before. ok=true means the round count is binding,
// including fail-closed: a bcrypt key whose options blob does not parse
// returns the maximum round count rather than ok=false, because the key is
// a bcrypt key and should be refused, not silently cracked. ssh.Unmarshal
// rejects such a blob as well, so the key could not have been decrypted at
// any round count.
func opensshBcryptRounds(pemBytes []byte) (rounds uint32, ok bool) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" ||
		len(block.Bytes) < len(privateKeyAuthMagic) ||
		string(block.Bytes[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return 0, false
	}

	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(block.Bytes[len(privateKeyAuthMagic):], &w); err != nil {
		return 0, false
	}
	if w.KdfName != "bcrypt" {
		return 0, false
	}

	ok = true

	var opts kdfOpts
	if err := ssh.Unmarshal([]byte(w.KdfOpts), &opts); err != nil {
		rounds = math.MaxUint32
	} else {
		rounds = opts.Rounds
	}

	return rounds, ok
}
