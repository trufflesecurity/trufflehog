package privatekey

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// ExtraData keys describing the key itself. Every value is read from the
// key's own bytes: nothing here touches the network, and nothing reveals the
// private half of the key.
const (
	// metaKeyType is rsa, ecdsa, ed25519, x25519, ecdsa-sk or ed25519-sk, or
	// the SSH algorithm name for any other key type SSH knows.
	metaKeyType = "key_type"
	// metaKeyBits is the RSA modulus size, or the size of the curve.
	metaKeyBits = "key_bits"
	// metaCurve is the NIST curve of an ECDSA key: P-224, P-256, P-384, P-521.
	metaCurve = "curve"
	// metaKeyFormat is the container the key was found in: pkcs1, pkcs8,
	// sec1 or openssh.
	metaKeyFormat = "key_format"
	// metaPublicKey is the public key as an authorized_keys line, for every
	// key type SSH can represent (not P-224 or X25519).
	metaPublicKey = "public_key"
	// metaSSHFingerprint is "SHA256:<base64>", as ssh-keygen -l, GitHub and
	// GitLab print it.
	metaSSHFingerprint = "ssh_fingerprint"
	// metaSPKISHA256 is the hex SHA-256 of the DER SubjectPublicKeyInfo, which
	// certificate search engines index (crt.sh: ?spkisha256=<value>).
	metaSPKISHA256 = "spki_sha256"
	// metaKeyComment is the comment of an unencrypted OpenSSH key, which
	// ssh-keygen sets to user@host unless told otherwise.
	metaKeyComment = "key_comment"
	// metaCipher, metaKDF and metaKDFRounds describe how an encrypted key is
	// protected. OpenSSH keys store all three in the clear; legacy OpenSSL PEM
	// keys name only the cipher.
	metaCipher    = "encryption_cipher"
	metaKDF       = "encryption_kdf"
	metaKDFRounds = "encryption_kdf_rounds"
)

// pemKeyFormats names the container behind each PEM type that
// ssh.ParseRawPrivateKey accepts.
var pemKeyFormats = map[string]string{
	"RSA PRIVATE KEY":     "pkcs1",
	"PRIVATE KEY":         "pkcs8",
	"EC PRIVATE KEY":      "sec1",
	"OPENSSH PRIVATE KEY": "openssh",
}

// Bounds, in runes, on values copied out of a key's own bytes, which can hold
// anything at all. Real cipher and KDF names are under 32 characters.
const (
	maxCommentLen = 256
	maxNameLen    = 64
)

// maxPublicKeyLen leaves public_key out for keys whose authorized_keys line is
// longer (RSA above about 6000 bits); their fingerprints still identify them.
// With the caps above, it keeps the metadata under 2 KB, so it cannot push a
// result's ExtraData past size limits downstream stores enforce (TruffleHog
// Enterprise refuses extra_data over 8192 characters).
const maxPublicKeyLen = 1024

// addKeyMetadata adds what can be read from a private key to extraData,
// leaving any key that is already present untouched. parsedKey is the key the
// detector decoded, or nil when the key is encrypted and was not cracked; then
// only what the container stores in the clear is reported, which for OpenSSH
// keys includes the public key.
//
// Metadata is best effort and must never cost a finding: anything that cannot
// be read is left out, and a panic while reading it is contained here.
func addKeyMetadata(extraData map[string]string, pemBytes []byte, parsedKey any) {
	if extraData == nil {
		return
	}
	defer func() { _ = recover() }()

	for k, v := range keyMetadata(pemBytes, parsedKey) {
		if _, ok := extraData[k]; !ok {
			extraData[k] = v
		}
	}
}

// keyMetadata returns what can be read from a private key; see addKeyMetadata.
func keyMetadata(pemBytes []byte, parsedKey any) map[string]string {
	md := make(map[string]string)

	var headerPublicKey ssh.PublicKey
	if block, _ := pem.Decode(pemBytes); block != nil {
		if format, ok := pemKeyFormats[block.Type]; ok {
			md[metaKeyFormat] = format
		}
		if block.Type == "OPENSSH PRIVATE KEY" {
			headerPublicKey = readOpenSSHHeader(md, block.Bytes)
		} else if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			// Legacy OpenSSL encryption: "DEK-Info: AES-128-CBC,<hex IV>".
			cipher, _, _ := strings.Cut(block.Headers["DEK-Info"], ",")
			setText(md, metaCipher, cipher, maxNameLen)
		}
	}

	if pub := publicKeyOf(parsedKey); pub != nil {
		describePublicKey(md, pub)
		if sshPub, err := ssh.NewPublicKey(pub); err == nil {
			describeSSHEncoding(md, sshPub)
		}
	} else if headerPublicKey != nil {
		describeSSHPublicKey(md, headerPublicKey)
	}

	return md
}

// publicKeyOf returns the public half of a key ssh.ParseRawPrivateKey
// returned, or nil for anything else, including keys too malformed to have
// one.
func publicKeyOf(parsedKey any) crypto.PublicKey {
	switch k := parsedKey.(type) {
	case *rsa.PrivateKey:
		if k != nil && k.N != nil {
			return &k.PublicKey
		}
	case *ecdsa.PrivateKey:
		// The coordinates are only checked for presence, because Bytes
		// dereferences them; Bytes then checks the point is on the curve.
		//nolint:staticcheck // SA1019: no non-deprecated way to see they are nil
		if k != nil && k.Curve != nil && k.X != nil && k.Y != nil {
			if _, err := k.PublicKey.Bytes(); err == nil {
				return &k.PublicKey
			}
		}
	case ed25519.PrivateKey: // PKCS #8
		if len(k) == ed25519.PrivateKeySize {
			return k.Public()
		}
	case *ed25519.PrivateKey: // OpenSSH
		if k != nil && len(*k) == ed25519.PrivateKeySize {
			return k.Public()
		}
	case *ecdh.PrivateKey: // PKCS #8 X25519
		if k != nil {
			return k.PublicKey()
		}
	}
	return nil
}

// describePublicKey records the type and size of pub, and its
// SubjectPublicKeyInfo hash.
func describePublicKey(md map[string]string, pub crypto.PublicKey) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		md[metaKeyType] = "rsa"
		md[metaKeyBits] = strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		params := k.Params()
		md[metaKeyType] = "ecdsa"
		md[metaKeyBits] = strconv.Itoa(params.BitSize)
		setText(md, metaCurve, params.Name, maxNameLen)
	case ed25519.PublicKey:
		md[metaKeyType] = "ed25519"
		md[metaKeyBits] = "256"
	case *ecdh.PublicKey:
		if k.Curve() != ecdh.X25519() {
			return
		}
		md[metaKeyType] = "x25519"
		md[metaKeyBits] = "256"
	default:
		return
	}

	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		sum := sha256.Sum256(der)
		md[metaSPKISHA256] = hex.EncodeToString(sum[:])
	}
}

// describeSSHPublicKey records what an SSH-encoded public key says about the
// key, for encrypted OpenSSH keys whose private half could not be read.
func describeSSHPublicKey(md map[string]string, pub ssh.PublicKey) {
	if cert, ok := pub.(*ssh.Certificate); ok {
		pub = cert.Key
	}

	switch pub.Type() {
	case ssh.KeyAlgoSKECDSA256:
		md[metaKeyType] = "ecdsa-sk"
		md[metaKeyBits] = "256"
		md[metaCurve] = "P-256"
	case ssh.KeyAlgoSKED25519:
		md[metaKeyType] = "ed25519-sk"
		md[metaKeyBits] = "256"
	default:
		if cryptoPub, ok := pub.(ssh.CryptoPublicKey); ok {
			describePublicKey(md, cryptoPub.CryptoPublicKey())
		}
		if _, ok := md[metaKeyType]; !ok {
			setText(md, metaKeyType, pub.Type(), maxNameLen)
		}
	}

	describeSSHEncoding(md, pub)
}

// describeSSHEncoding records pub as an authorized_keys line, unless that is
// longer than maxPublicKeyLen, and its SHA-256 fingerprint.
func describeSSHEncoding(md map[string]string, pub ssh.PublicKey) {
	if line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n"); len(line) <= maxPublicKeyLen {
		md[metaPublicKey] = line
	}
	md[metaSSHFingerprint] = fingerprintSSHPublicKey(pub)
}

// readOpenSSHHeader records the parts of an OpenSSH private key that are
// stored in the clear: cipher, KDF and, when the key is not encrypted, the
// comment. It returns the embedded public key, or nil. The layout is in
// PROTOCOL.key in the OpenSSH source distribution.
func readOpenSSHHeader(md map[string]string, der []byte) ssh.PublicKey {
	if len(der) < len(privateKeyAuthMagic) || string(der[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return nil
	}
	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(der[len(privateKeyAuthMagic):], &w); err != nil || w.NumKeys != 1 {
		return nil
	}

	if w.CipherName == "none" {
		setText(md, metaKeyComment, openSSHComment(w.PrivKeyBlock), maxCommentLen)
	} else {
		setText(md, metaCipher, w.CipherName, maxNameLen)
	}
	if w.KdfName != "none" {
		setText(md, metaKDF, w.KdfName, maxNameLen)
	}
	if w.KdfName == "bcrypt" {
		var opts kdfOpts
		if err := ssh.Unmarshal([]byte(w.KdfOpts), &opts); err == nil {
			md[metaKDFRounds] = strconv.FormatUint(uint64(opts.Rounds), 10)
		}
	}

	pub, err := ssh.ParsePublicKey(w.PubKey)
	if err != nil {
		return nil
	}
	return pub
}

// openSSHComment returns the comment from an unencrypted OpenSSH private key
// block, or "" if the block does not parse. The comment follows the key's
// private fields, whose layout depends on the key type; the layouts mirror
// x/crypto's (ssh/keys.go), with mpints read as plain strings because only
// their length matters here.
func openSSHComment(block []byte) string {
	var pk struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(block, &pk); err != nil || pk.Check1 != pk.Check2 {
		return ""
	}

	switch pk.Keytype {
	case ssh.KeyAlgoRSA:
		var k struct {
			N, E, D, Iqmp, P, Q []byte
			Comment             string
			Pad                 []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(pk.Rest, &k) == nil {
			return k.Comment
		}
	case ssh.KeyAlgoED25519:
		var k struct {
			Pub, Priv []byte
			Comment   string
			Pad       []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(pk.Rest, &k) == nil {
			return k.Comment
		}
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		var k struct {
			Curve   string
			Pub, D  []byte
			Comment string
			Pad     []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(pk.Rest, &k) == nil {
			return k.Comment
		}
	}
	return ""
}

// setText records a value copied from the key's own bytes, if anything is
// left of it once it is made safe to print and to store: valid UTF-8, which
// protobuf string fields require, no control or format characters, which
// would reach terminals verbatim, and at most maxLen runes.
func setText(md map[string]string, key, value string, maxLen int) {
	if len(value) > 4*maxLen {
		value = value[:4*maxLen]
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	value = strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf) {
			return -1
		}
		return r
	}, value)
	if runes := []rune(value); len(runes) > maxLen {
		value = string(runes[:maxLen])
	}
	if value = strings.TrimSpace(value); value != "" {
		md[key] = value
	}
}
