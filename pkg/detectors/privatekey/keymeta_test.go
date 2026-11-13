package privatekey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// loadFixture reads a throwaway key from testdata. See testdata/README.md:
// every fixture was generated for these tests and none is a real key.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

// fixtureToken returns a fixture the way production sees it: normalized
// like a regex match inside FromData.
func fixtureToken(t *testing.T, name string) []byte {
	t.Helper()
	return []byte(Normalize(string(loadFixture(t, name))))
}

func TestParseKeyMetadata_EncryptedOpenSSH16Rounds(t *testing.T) {
	meta := parseKeyMetadata(fixtureToken(t, "encrypted_openssh_ed25519_a16"))
	assert.Equal(t, "openssh", meta.format)
	assert.Equal(t, "aes256-ctr", meta.cipher)
	assert.Equal(t, "bcrypt", meta.kdf)
	assert.Equal(t, uint32(16), meta.kdfRounds)
	assert.Equal(t, "<=16", meta.kdfRoundsLabel())
}

// The 2048-round key is parse-only: the round count must be readable from
// the cleartext header without paying a single bcrypt attempt, because at
// 2048 rounds each attempt costs seconds.
func TestParseKeyMetadata_EncryptedOpenSSH2048Rounds(t *testing.T) {
	meta := parseKeyMetadata(fixtureToken(t, "encrypted_openssh_ed25519_a2048"))
	assert.Equal(t, "openssh", meta.format)
	assert.Equal(t, "aes256-ctr", meta.cipher)
	assert.Equal(t, "bcrypt", meta.kdf)
	assert.Equal(t, uint32(2048), meta.kdfRounds)
	assert.Equal(t, ">256", meta.kdfRoundsLabel())
}

func TestParseKeyMetadata_EncryptedLegacyPEM(t *testing.T) {
	meta := parseKeyMetadata(fixtureToken(t, "encrypted_pem_rsa"))
	assert.Equal(t, "pem", meta.format)
	// The legacy PEM header carries no cipher, KDF, or round information.
	assert.Empty(t, meta.cipher)
	assert.Empty(t, meta.kdf)
	assert.Zero(t, meta.kdfRounds)
	assert.Equal(t, "unknown", meta.kdfRoundsLabel())
}

func TestParseKeyMetadata_UnencryptedOpenSSH(t *testing.T) {
	meta := parseKeyMetadata(fixtureToken(t, "unencrypted_openssh_ed25519"))
	assert.Equal(t, "openssh", meta.format)
	assert.Equal(t, "none", meta.cipher)
	assert.Equal(t, "none", meta.kdf)
	assert.Zero(t, meta.kdfRounds)
	assert.Equal(t, "unknown", meta.kdfRoundsLabel())
}

func TestParseKeyMetadata_TruncatedGarbage(t *testing.T) {
	meta := parseKeyMetadata(fixtureToken(t, "truncated_openssh_garbage"))
	assert.Equal(t, "unknown", meta.format)
	assert.Equal(t, "unknown", meta.kdfRoundsLabel())
}

// TestParseKeyMetadata_LegacyCBCCiphers pins the other side of the cipher
// bounding: every cipher value OpenSSH has accepted for private-key
// encryption - including the CBC family that predates the aes256-ctr
// default - must pass through boundHeaderField verbatim, because legacy
// keys legitimately carry these names and collapsing them to "other"
// would hide the one signal that distinguishes an old key from an
// attacker-controlled header.
func TestParseKeyMetadata_LegacyCBCCiphers(t *testing.T) {
	for _, cipher := range []string{"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"} {
		kdfOptions := append(append(u32be(16), make([]byte, 16)...), u32be(16)...)
		key := wrapOpenSSHPEM(t, hostileBody(sshField(cipher), sshField("bcrypt"), sshField(string(kdfOptions))))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "openssh", meta.format)
		assert.Equal(t, cipher, meta.cipher, "a legacy CBC cipher name is a legitimate header value and must not collapse to \"other\"")
		assert.Equal(t, "bcrypt", meta.kdf)
	}
}

// hostileBody builds an OpenSSH binary header body out of raw field bytes
// so tests can present attacker-controlled lengths and shapes.
func hostileBody(fields ...[]byte) []byte {
	body := bytes.NewBuffer(opensshMagic)
	for _, f := range fields {
		body.Write(f)
	}
	return body.Bytes()
}

func u32be(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// sshField encodes one length-prefixed OpenSSH header string.
func sshField(s string) []byte {
	return append(u32be(uint32(len(s))), s...)
}

// wrapOpenSSHPEM PEM-wraps a binary body the way an OpenSSH key file looks.
func wrapOpenSSHPEM(t *testing.T, body []byte) []byte {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString(body)
	var out strings.Builder
	out.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(encoded) > 70 {
		out.WriteString(encoded[:70] + "\n")
		encoded = encoded[70:]
	}
	out.WriteString(encoded + "\n")
	out.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
	return []byte(out.String())
}

// TestParseKeyMetadata_HostileHeader feeds the parser header bytes a
// malformed key could carry: declared lengths of 0xFFFFFFFF, a salt length
// that overruns its field, truncations, and unrecognized cipher and KDF
// names. Every length prefix and field value is attacker-controlled, so
// the contract is that each case either reports format "unknown" or bounds
// the value - and completing this test at all is the no-panic assertion.
func TestParseKeyMetadata_HostileHeader(t *testing.T) {
	t.Run("hostile ciphername length", func(t *testing.T) {
		key := wrapOpenSSHPEM(t, hostileBody(u32be(0xFFFFFFFF), []byte("aes256-ctr")))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "unknown", meta.format)
	})
	t.Run("hostile kdfname length", func(t *testing.T) {
		key := wrapOpenSSHPEM(t, hostileBody(sshField("aes256-ctr"), u32be(0xFFFFFFFF), []byte("bcrypt")))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "unknown", meta.format)
	})
	t.Run("hostile kdfoptions length", func(t *testing.T) {
		key := wrapOpenSSHPEM(t, hostileBody(sshField("aes256-ctr"), sshField("bcrypt"), u32be(0xFFFFFFFF), []byte("junk")))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "unknown", meta.format)
	})
	t.Run("hostile salt length inside kdfoptions", func(t *testing.T) {
		kdfOptions := append(u32be(0xFFFFFFFF), 'x')
		key := wrapOpenSSHPEM(t, hostileBody(sshField("aes256-ctr"), sshField("bcrypt"), sshField(string(kdfOptions))))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "unknown", meta.format)
	})
	t.Run("kdfoptions truncated before rounds", func(t *testing.T) {
		kdfOptions := append(u32be(16), make([]byte, 16)...) // salt, no rounds
		key := wrapOpenSSHPEM(t, hostileBody(sshField("aes256-ctr"), sshField("bcrypt"), sshField(string(kdfOptions))))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "unknown", meta.format)
	})
	t.Run("missing openssh magic", func(t *testing.T) {
		key := wrapOpenSSHPEM(t, []byte("this is not an openssh key"))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "unknown", meta.format)
	})
	t.Run("not PEM at all", func(t *testing.T) {
		meta := parseKeyMetadata([]byte("garbage that is not PEM"))
		assert.Equal(t, "unknown", meta.format)
	})
	t.Run("unrecognized cipher and kdf collapse to other", func(t *testing.T) {
		key := wrapOpenSSHPEM(t, hostileBody(sshField("rot13-cipher"), sshField("scrypt"), sshField("")))
		meta := parseKeyMetadata(key)
		assert.Equal(t, "openssh", meta.format)
		assert.Equal(t, "other", meta.cipher, "an unrecognized cipher name must never reach a log line verbatim")
		assert.Equal(t, "other", meta.kdf, "an unrecognized KDF name must never reach a log line verbatim")
		assert.Zero(t, meta.kdfRounds, "an unrecognized KDF leaves the round count unset")
	})
}

func TestCrackOutcome(t *testing.T) {
	assert.Equal(t, crackOutcomeCracked, crackOutcome(nil))
	assert.Equal(t, crackOutcomeUncrackable, crackOutcome(ErrUncrackable))
	assert.Equal(t, crackOutcomeUncrackable, crackOutcome(fmt.Errorf("wrapped: %w", ErrUncrackable)))
	assert.Equal(t, crackOutcomeFailed, crackOutcome(errors.New("key could not be attempted")))
	assert.Equal(t, crackOutcomeAborted, crackOutcome(context.Canceled))
	assert.Equal(t, crackOutcomeAborted, crackOutcome(context.DeadlineExceeded))
	assert.Equal(t, crackOutcomeAborted, crackOutcome(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)))
}

// TestCrackWrapperKeepsSignature pins the exported contract the
// privatekey analyzer and external importers depend on: same inputs, same
// three returns.
func TestCrackWrapperKeepsSignature(t *testing.T) {
	parsed, passphrase, err := Crack(fixtureToken(t, "crackable_openssh_ed25519_a16"))
	require.NoError(t, err)
	assert.Equal(t, "password", passphrase)
	assert.NotNil(t, parsed)
}

// Test_crack_StopsOnDoneContext pins the walk's deadline behavior: the
// KDF cost is linear in the round count stored in the key file, so a full
// walk on one expensive key can outlast any caller's deadline. A walk
// whose context is already done must stop before the first derivation.
func Test_crack_StopsOnDoneContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := crack(ctx, fixtureToken(t, "encrypted_openssh_ed25519_a16"))
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, res.attempts, "a done context must stop the walk before the first attempt")
}

// errAfterContext implements the minimum context.Context surface for
// crack's deadline check: Err() reports nil for the first callsBeforeDone
// calls, then the context is done. crack consults Err() once per loop
// iteration, so the stub makes the abort land after a known number of
// attempts.
type errAfterContext struct {
	callsBeforeDone int
	calls           int
}

func (c *errAfterContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *errAfterContext) Done() <-chan struct{}       { return nil }
func (c *errAfterContext) Value(any) any               { return nil }

func (c *errAfterContext) Err() error {
	c.calls++
	if c.calls <= c.callsBeforeDone {
		return nil
	}
	return context.Canceled
}

// Test_crack_AbortsMidWalk pins the between-attempts deadline check with a
// deterministic context: the walk runs its first attempt, then notices the
// done context before starting a second, so it stops mid-walk with the
// context error rather than ErrUncrackable.
func Test_crack_AbortsMidWalk(t *testing.T) {
	ctx := &errAfterContext{callsBeforeDone: 1}

	res, err := crack(ctx, fixtureToken(t, "encrypted_openssh_ed25519_a16"))
	assert.ErrorIs(t, err, context.Canceled)
	assert.GreaterOrEqual(t, res.attempts, 1,
		"the walk must have started at least one attempt before the deadline was noticed")
	assert.Equal(t, crackOutcomeAborted, crackOutcome(err))
	assert.NotErrorIs(t, err, ErrUncrackable)
}

// crackLogEntry is one captured log call.
type crackLogEntry struct {
	level         int
	msg           string
	err           error
	keysAndValues []any
}

// fieldsMap pairs up the alternating key/value arguments of a log call.
func (e crackLogEntry) fieldsMap() map[string]any {
	m := make(map[string]any, len(e.keysAndValues)/2)
	for i := 0; i+1 < len(e.keysAndValues); i += 2 {
		if k, ok := e.keysAndValues[i].(string); ok {
			m[k] = e.keysAndValues[i+1]
		}
	}
	return m
}

// crackLogCore is the shared state of a sink and every sink derived from
// it through WithValues/WithName.
type crackLogCore struct {
	mu      sync.Mutex
	entries []crackLogEntry
}

func (c *crackLogCore) findMsg(msg string) (crackLogEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		if e.msg == msg {
			return e, true
		}
	}
	return crackLogEntry{}, false
}

func (c *crackLogCore) countMsg(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.entries {
		if e.msg == msg {
			n++
		}
	}
	return n
}

// renderAll flattens every captured entry into one searchable string, the
// way a real sink would emit it, so leak assertions cover everything
// logged during the test.
func (c *crackLogCore) renderAll() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, e := range c.entries {
		fmt.Fprintf(&b, "%v %v", e.msg, e.err)
		for _, v := range e.keysAndValues {
			fmt.Fprintf(&b, " %v", v)
		}
	}
	return b.String()
}

// crackLogSink captures log entries for assertions. Enabled always returns
// true so V(2) lines reach the entries even though the default logger
// would filter them.
type crackLogSink struct {
	core  *crackLogCore
	bound []any
}

func newCrackLogSink() *crackLogSink {
	return &crackLogSink{core: &crackLogCore{}}
}

func (s *crackLogSink) Init(logr.RuntimeInfo) {}

func (s *crackLogSink) Enabled(int) bool { return true }

func (s *crackLogSink) Info(level int, msg string, kvs ...any) {
	s.record(level, msg, nil, kvs)
}

func (s *crackLogSink) Error(err error, msg string, kvs ...any) {
	s.record(-1, msg, err, kvs)
}

func (s *crackLogSink) record(level int, msg string, err error, kvs []any) {
	all := append(append([]any(nil), s.bound...), kvs...)
	s.core.mu.Lock()
	defer s.core.mu.Unlock()
	s.core.entries = append(s.core.entries, crackLogEntry{level: level, msg: msg, err: err, keysAndValues: all})
}

func (s *crackLogSink) WithValues(kvs ...any) logr.LogSink {
	return &crackLogSink{core: s.core, bound: append(append([]any(nil), s.bound...), kvs...)}
}

func (s *crackLogSink) WithName(string) logr.LogSink { return s }

// crackSampleCount reads the _count series of the crack duration histogram
// for one label combination: the number of observations recorded so far.
func crackSampleCount(t *testing.T, format, rounds string) uint64 {
	t.Helper()
	observer := crackDuration.WithLabelValues(format, rounds)
	metric, ok := observer.(prometheus.Metric)
	require.True(t, ok, "histogram observer must expose its metric for reading")
	pb := &dto.Metric{}
	require.NoError(t, metric.Write(pb))
	return pb.GetHistogram().GetSampleCount()
}

// crackLabelValues collects every label value the histogram carries, so
// leak assertions can check that no secret material became a label.
func crackLabelValues(t *testing.T) []string {
	t.Helper()
	ch := make(chan prometheus.Metric, 16)
	go func() {
		crackDuration.Collect(ch)
		close(ch)
	}()
	var values []string
	for metric := range ch {
		pb := &dto.Metric{}
		require.NoError(t, metric.Write(pb))
		for _, label := range pb.GetLabel() {
			values = append(values, label.GetValue())
		}
	}
	return values
}

// fixtureSalt extracts the bcrypt salt from an OpenSSH fixture. It
// duplicates the header walk on purpose: parseKeyMetadata deliberately
// never returns key material, so the test needs its own reader to know
// what must not leak.
func fixtureSalt(t *testing.T, key []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(key)
	require.NotNil(t, block, "fixture must be PEM")
	b := block.Bytes
	require.True(t, bytes.HasPrefix(b, opensshMagic), "fixture must be OpenSSH format")
	b = b[len(opensshMagic):]
	readField := func() []byte {
		require.GreaterOrEqual(t, len(b), 4)
		n := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		require.GreaterOrEqual(t, len(b), int(n))
		v := b[:n]
		b = b[n:]
		return v
	}
	readField() // ciphername
	readField() // kdfname
	kdfOptions := readField()
	require.GreaterOrEqual(t, len(kdfOptions), 4)
	saltLen := binary.BigEndian.Uint32(kdfOptions[:4])
	require.GreaterOrEqual(t, len(kdfOptions), int(4+saltLen))
	return kdfOptions[4 : 4+saltLen]
}

// wordlistPosition returns the 1-based attempt count at which crack should
// recover passphrase, or 0 when the passphrase is not in the wordlist.
func wordlistPosition(passphrase string) int {
	for i, p := range passphrases {
		if string(p) == passphrase {
			return i + 1
		}
	}
	return 0
}

// assertNoSecretMaterialLeaked is the hygiene contract of the crack
// instrumentation: the key bytes (whose base64 body embeds the salt), the
// salt itself, and the passphrase must appear in no log output and no
// metric label value - including on the cracked path, where the passphrase
// is a live value in the process.
func assertNoSecretMaterialLeaked(t *testing.T, sink *crackLogSink, key []byte, passphrase string) {
	t.Helper()
	rendered := sink.core.renderAll()

	// The full key: any appearance of its base64 body means key bytes
	// reached the log.
	var body strings.Builder
	for _, line := range strings.Split(string(key), "\n") {
		if !strings.Contains(line, "PRIVATE KEY") && !strings.Contains(line, "Proc-Type") && !strings.Contains(line, "DEK-Info") {
			body.WriteString(strings.TrimSpace(line))
		}
	}
	assert.NotContains(t, rendered, body.String(), "log output must not contain the key")

	block, _ := pem.Decode(key)
	if block != nil && bytes.HasPrefix(block.Bytes, opensshMagic) {
		salt := fixtureSalt(t, key)
		assert.NotContains(t, rendered, string(salt), "log output must not contain the KDF salt")
		assert.NotContains(t, rendered, hex.EncodeToString(salt), "log output must not contain the KDF salt in hex")
		assert.NotContains(t, rendered, base64.StdEncoding.EncodeToString(salt), "log output must not contain the KDF salt in base64")
	}
	if passphrase != "" {
		assert.NotContains(t, rendered, passphrase, "log output must not contain the passphrase")
	}
	for _, labelValue := range crackLabelValues(t) {
		assert.NotContains(t, labelValue, passphrase, "metric labels must not contain the passphrase")
		assert.NotContains(t, labelValue, body.String(), "metric labels must not contain the key")
	}
}

// findCrackLogEntry returns the single crack log line captured by sink and
// fails the test when it is missing or duplicated.
func findCrackLogEntry(t *testing.T, sink *crackLogSink) crackLogEntry {
	t.Helper()
	require.Equal(t, 1, sink.core.countMsg(crackLogMsg), "expected exactly one crack log line per encrypted key")
	entry, ok := sink.core.findMsg(crackLogMsg)
	require.True(t, ok, "expected the crack log line to be captured")
	return entry
}

func TestFromData_CrackInstrumentation_CrackedOpenSSH(t *testing.T) {
	sink := newCrackLogSink()
	ctx := logContext.WithLogger(context.Background(), logr.New(sink))
	key := fixtureToken(t, "crackable_openssh_ed25519_a16")

	wantAttempts := wordlistPosition("password")
	require.NotZero(t, wantAttempts, "fixture passphrase must be in the built-in wordlist")

	before := crackSampleCount(t, "openssh", "<=16")
	results, err := Scanner{}.FromData(ctx, false, key)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "true", results[0].ExtraData["encrypted"])
	assert.Equal(t, "true", results[0].ExtraData["cracked_encryption_passphrase"])
	assert.Equal(t, before+1, crackSampleCount(t, "openssh", "<=16"),
		"the crack duration histogram should record one observation per encrypted key")

	assertNoSecretMaterialLeaked(t, sink, key, "password")

	entry := findCrackLogEntry(t, sink)
	fields := entry.fieldsMap()
	assert.Equal(t, 2, entry.level, "the crack log line must be V(2)")
	assert.Equal(t, "openssh", fields["format"])
	assert.Equal(t, "aes256-ctr", fields["cipher"])
	assert.Equal(t, "bcrypt", fields["kdf"])
	assert.Equal(t, "<=16", fields["kdf_rounds"])
	assert.Equal(t, wantAttempts, fields["attempts"])
	assert.Equal(t, crackOutcomeCracked, fields["outcome"])
	assert.NotEmpty(t, fields["duration"])
	assert.NotContains(t, fields, "error", "a successful crack carries no error field")
}

func TestFromData_CrackInstrumentation_UncrackableLegacyPEM(t *testing.T) {
	sink := newCrackLogSink()
	ctx := logContext.WithLogger(context.Background(), logr.New(sink))
	key := fixtureToken(t, "encrypted_pem_rsa")

	// A legacy PEM attempt costs a cheap block cipher decrypt rather than
	// bcrypt, so the full wordlist walk stays fast.
	before := crackSampleCount(t, "pem", "unknown")
	results, err := Scanner{}.FromData(ctx, false, key)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "true", results[0].ExtraData["encrypted"])
	assert.Equal(t, before+1, crackSampleCount(t, "pem", "unknown"),
		"the uncrackable path must still observe the histogram")

	entry := findCrackLogEntry(t, sink)
	fields := entry.fieldsMap()
	assert.Equal(t, 2, entry.level)
	assert.Equal(t, "pem", fields["format"])
	assert.Empty(t, fields["cipher"])
	assert.Empty(t, fields["kdf"])
	assert.Equal(t, "unknown", fields["kdf_rounds"])
	assert.Equal(t, len(passphrases), fields["attempts"],
		"an uncrackable key must report a full wordlist walk")
	assert.Equal(t, crackOutcomeUncrackable, fields["outcome"])
	assert.NotEmpty(t, fields["duration"])
	assert.NotContains(t, fields, "error", "the uncrackable outcome carries no extra information and no error field")

	assertNoSecretMaterialLeaked(t, sink, key, "trufflehog-test-fixture")
}

func TestFromData_CrackInstrumentation_UncrackableOpenSSH16Rounds(t *testing.T) {
	sink := newCrackLogSink()
	ctx := logContext.WithLogger(context.Background(), logr.New(sink))
	key := fixtureToken(t, "encrypted_openssh_ed25519_a16")

	// The fixture passphrase is not in the wordlist, so this walks all of
	// it at 16 bcrypt rounds - the deliberately-slow case the histogram
	// exists to time. No test ever does this with the 2048-round fixture.
	before := crackSampleCount(t, "openssh", "<=16")
	results, err := Scanner{}.FromData(ctx, false, key)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "true", results[0].ExtraData["encrypted"])
	assert.Equal(t, before+1, crackSampleCount(t, "openssh", "<=16"))

	entry := findCrackLogEntry(t, sink)
	fields := entry.fieldsMap()
	assert.Equal(t, 2, entry.level)
	assert.Equal(t, "openssh", fields["format"])
	assert.Equal(t, "aes256-ctr", fields["cipher"])
	assert.Equal(t, "bcrypt", fields["kdf"])
	assert.Equal(t, "<=16", fields["kdf_rounds"])
	assert.Equal(t, len(passphrases), fields["attempts"])
	assert.Equal(t, crackOutcomeUncrackable, fields["outcome"])
	assert.NotEmpty(t, fields["duration"])
	assert.NotContains(t, fields, "error", "the uncrackable outcome carries no extra information and no error field")

	assertNoSecretMaterialLeaked(t, sink, key, "trufflehog-test-fixture")
}

// The abort counterpart of the instrumentation family: when the scan
// deadline fires before or during the walk, the log line must say so
// through its outcome rather than misreporting a parse failure, and the
// finding still surfaces - an encrypted key that was never cracked is a
// real exposure either way.
func TestFromData_CrackInstrumentation_AbortedWalk(t *testing.T) {
	sink := newCrackLogSink()
	baseCtx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx := logContext.WithLogger(baseCtx, logr.New(sink))
	key := fixtureToken(t, "encrypted_openssh_ed25519_a16")

	before := crackSampleCount(t, "openssh", "<=16")
	results, err := Scanner{}.FromData(ctx, false, key)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "true", results[0].ExtraData["encrypted"])
	assert.Equal(t, before+1, crackSampleCount(t, "openssh", "<=16"),
		"an aborted walk still held its worker for the observed time and must stay in the histogram")

	entry := findCrackLogEntry(t, sink)
	fields := entry.fieldsMap()
	assert.Equal(t, 2, entry.level)
	assert.Equal(t, "openssh", fields["format"])
	assert.Equal(t, "aes256-ctr", fields["cipher"])
	assert.Equal(t, "bcrypt", fields["kdf"])
	assert.Equal(t, "<=16", fields["kdf_rounds"])
	assert.Equal(t, 0, fields["attempts"], "a done context must stop the walk before the first attempt")
	assert.Equal(t, crackOutcomeAborted, fields["outcome"])
	assert.NotEmpty(t, fields["duration"])
	assert.NotContains(t, fields, "error", "an aborted walk is not a key parse failure and carries no error field")
}

func TestFromData_CrackInstrumentation_FailedOutcome(t *testing.T) {
	sink := newCrackLogSink()
	ctx := logContext.WithLogger(context.Background(), logr.New(sink))

	// A legacy-PEM-shaped block whose encrypted body cannot decrypt: the
	// first passphrase attempt dies on a parse failure rather than a
	// wrong-password error, so the walk stops with outcome "failed" after
	// one attempt.
	failedKey := []byte(`-----BEGIN ACME PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,0123456789ABCDEF

QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=
-----END ACME PRIVATE KEY-----
`)

	before := crackSampleCount(t, "pem", "unknown")
	results, err := Scanner{}.FromData(ctx, false, failedKey)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "true", results[0].ExtraData["encrypted"])
	assert.Equal(t, before+1, crackSampleCount(t, "pem", "unknown"),
		"the failed path must still observe the histogram")

	entry := findCrackLogEntry(t, sink)
	fields := entry.fieldsMap()
	assert.Equal(t, 2, entry.level)
	assert.Equal(t, "pem", fields["format"])
	assert.Equal(t, 1, fields["attempts"], "a non-password parse failure stops the walk on the first attempt")
	assert.Equal(t, crackOutcomeFailed, fields["outcome"])
	assert.Equal(t, crackFailedErrorField, fields["error"],
		"the error field must carry the fixed classifier, never raw error text")

	// The log line carries only the classifier, so the underlying parse
	// error must ride the finding's verification error. It arrives as
	// redacted plain text, so the pin is on its message.
	verr := results[0].VerificationError()
	require.Error(t, verr)
	assert.Contains(t, verr.Error(), "ssh: cannot decode encrypted private keys",
		"the parse error itself, not just its classifier, must ride the finding")
	assert.NotContains(t, verr.Error(), crackFailedErrorField,
		"the log classifier is a log field, not a stand-in for the finding's error")

	// The PEM block type is attacker-influenced input that ssh's error
	// strings can embed; it must not reach the log.
	assert.NotContains(t, sink.core.renderAll(), "ACME")
}
