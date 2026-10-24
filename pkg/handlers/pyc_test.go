package handlers

import (
	"bytes"
	"encoding/hex"
	regexp "github.com/wasilibs/go-re2"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailgun"
)

// Fixture: testdata/pyc_secret.pyc was compiled (CPython 3.12) from
//
//	mailgun_legacy = "e7ceb5d23e4f015ea0e4cb6cd388ada65adde9519d34aeb3d6cd49fabc6a9d4832248376"
//
// The 72-char token matches mailgun's "Original MailGun" pattern, which is
// keyword-prefixed and therefore only matches when the keyword precedes the
// secret.
const (
	pycToken   = "e7ceb5d23e4f015ea0e4cb6cd388ada65adde9519d34aeb3d6cd49fabc6a9d4832248376"
	pycKeyword = "mailgun_legacy"
)

// Regression test for https://github.com/trufflesecurity/trufflehog/issues/5430.
//
// A credential compiled into a .pyc file is stored as a plaintext string in
// the marshal payload, yet TruffleHog reported zero chunks for it: the
// content-detected ".pyc" extension hit common.IsBinary and the file was
// silently skipped in handleNonArchiveContent.
func TestPythonBytecodeIsScanned(t *testing.T) {
	file, err := os.Open("testdata/pyc_secret.pyc")
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer func() { _ = rdr.Close() }()

	// Sanity check: the fixture must actually be detected as Python bytecode,
	// otherwise this test is not exercising the reported code path.
	assert.Equal(t, ".pyc", rdr.mime.Extension())

	handler := newDefaultHandler(defaultHandlerType)
	var chunks [][]byte
	for dataOrErr := range handler.HandleFile(context.AddLogger(ctx), rdr) {
		require.NoError(t, dataOrErr.Err)
		if len(dataOrErr.Data) > 0 {
			chunks = append(chunks, dataOrErr.Data)
		}
	}

	require.NotEmpty(t, chunks, "expected .pyc content to produce chunks, got none")

	var combined []byte
	for _, c := range chunks {
		combined = append(combined, c...)
	}
	assert.Contains(t, string(combined), pycKeyword)
	assert.Contains(t, string(combined), pycToken)
}

// collectChunks runs raw bytes through the default handler as Python bytecode
// content and returns everything it emits.
func collectChunks(t *testing.T, raw []byte) []byte {
	t.Helper()

	mtr, err := newMimeTypeReader(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, ".pyc", mtr.mimeExt, "test input must be detected as Python bytecode")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handler := newDefaultHandler(defaultHandlerType)
	dataOrErrChan := make(chan DataOrErr, defaultBufferSize)
	require.NoError(t, handler.handleNonArchiveContent(context.AddLogger(ctx), mtr, dataOrErrChan))
	close(dataOrErrChan)

	var combined []byte
	for dataOrErr := range dataOrErrChan {
		require.NoError(t, dataOrErr.Err)
		combined = append(combined, dataOrErr.Data...)
	}
	return combined
}

// The fixture's raw marshal bytes store the secret (in co_consts) ahead of the
// identifier naming it (in co_names). Keyword-prefixed detectors require the
// keyword first, so they can never match the raw bytes; the handler must emit
// the content in an order where the keyword precedes the secret. Regression
// test for the second cause in
// https://github.com/trufflesecurity/trufflehog/issues/5430.
func TestPythonBytecodeKeywordBeforeSecret(t *testing.T) {
	raw, err := os.ReadFile("testdata/pyc_secret.pyc")
	require.NoError(t, err)

	// Sanity check on the fixture: marshal really does write the secret
	// before the keyword in the raw bytes.
	secretIdx := bytes.Index(raw, []byte(pycToken))
	keywordIdx := bytes.Index(raw, []byte(pycKeyword))
	require.NotEqual(t, -1, secretIdx)
	require.NotEqual(t, -1, keywordIdx)
	require.Less(t, secretIdx, keywordIdx, "fixture must have secret before keyword in raw marshal bytes")

	// A PrefixRegex detector cannot match the raw bytes ...
	pattern := regexp.MustCompile(detectors.PrefixRegex([]string{"mailgun"}) + `\b([a-zA-Z0-9-]{72})\b`)
	assert.Empty(t, pattern.FindAllString(string(raw), -1),
		"prefix detector unexpectedly matched raw .pyc bytes")

	// ... but it must match what the handler emits for the same content.
	emitted := collectChunks(t, raw)
	var secrets []string
	for _, m := range pattern.FindAllStringSubmatch(string(emitted), -1) {
		secrets = append(secrets, m[1])
	}
	require.NotEmpty(t, secrets, "prefix detector did not match handler output for .pyc content")
	assert.Contains(t, secrets, pycToken)
}

// End-to-end at the handler+detector level: the chunks produced for a .pyc
// file must let a real keyword-prefixed detector (mailgun) find the secrets.
func TestPythonBytecodeDetectorFindsSecret(t *testing.T) {
	raw, err := os.ReadFile("testdata/pyc_secret.pyc")
	require.NoError(t, err)

	combined := collectChunks(t, raw)
	require.NotEmpty(t, combined)

	scanner := mailgun.Scanner{}
	results, err := scanner.FromData(context.AddLogger(context.Background()), false, combined)
	require.NoError(t, err)

	found := make(map[string]bool)
	for _, r := range results {
		found[string(r.Raw)] = true
	}
	assert.True(t, found[pycToken], "mailgun detector missed the token in .pyc chunks")
}

// A .pyc nested inside an archive must also be scanned rather than skipped
// by the archive handler's binary-extension check. Regression test for
// https://github.com/trufflesecurity/trufflehog/issues/5430.
func TestPythonBytecodeInArchiveIsScanned(t *testing.T) {
	file, err := os.Open("testdata/pyc_in_zip.zip")
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer func() { _ = rdr.Close() }()
	require.True(t, rdr.isGenericArchive, "fixture must be detected as an archive")

	handler := newArchiveHandler()
	var combined []byte
	for dataOrErr := range handler.HandleFile(context.AddLogger(ctx), rdr) {
		require.NoError(t, dataOrErr.Err)
		combined = append(combined, dataOrErr.Data...)
	}

	require.NotEmpty(t, combined, "expected .pyc inside archive to produce chunks, got none")
	assert.Contains(t, string(combined), pycToken)
	assert.Contains(t, string(combined), pycKeyword)
}

// Fixture: testdata/pyc_multi.pyc was compiled (CPython 3.12) from
//
//	mailgun_secondary = "36d330d315ae02721ebfbf6a17cf85e4fe7469e00b08121536e12e0def6866b67ad00111"
//	deployment_note = "deliberately-long-second-string-literal-to-widen-the-keyword-gap-0123456789"
//
// Regression test for the review finding on PR #5434: emitting the flat
// marshal string list in reverse puts a later co_consts value between an
// earlier secret's keyword and the secret itself, pushing the keyword past
// PrefixRegex's 40-character window so keyword-prefixed detectors miss it.
// The handler must emit each code object's identifiers adjacent to the
// values they name.
const (
	pycMultiToken   = "36d330d315ae02721ebfbf6a17cf85e4fe7469e00b08121536e12e0def6866b67ad00111"
	pycMultiKeyword = "mailgun_secondary"
)

func TestPythonBytecodeMultiAssignmentKeywordBeforeSecret(t *testing.T) {
	raw, err := os.ReadFile("testdata/pyc_multi.pyc")
	require.NoError(t, err)

	emitted := collectChunks(t, raw)
	require.NotEmpty(t, emitted, "expected .pyc content to produce chunks, got none")

	pattern := regexp.MustCompile(detectors.PrefixRegex([]string{"mailgun"}) + `\b([a-f0-9]{72})\b`)
	var secrets []string
	for _, m := range pattern.FindAllStringSubmatch(string(emitted), -1) {
		secrets = append(secrets, m[1])
	}
	require.NotEmpty(t, secrets, "prefix detector missed every secret in multi-assignment .pyc output")
	assert.Contains(t, secrets, pycMultiToken)

	// The keyword must directly precede its secret: no unrelated literal may
	// sit between them.
	kwIdx := bytes.Index(emitted, []byte(pycMultiKeyword))
	secIdx := bytes.Index(emitted, []byte(pycMultiToken))
	require.NotEqual(t, -1, kwIdx)
	require.NotEqual(t, -1, secIdx)
	require.Less(t, kwIdx, secIdx, "keyword must precede the secret in handler output")
	assert.Less(t, secIdx-kwIdx, 40, "keyword/secret gap must fit PrefixRegex's window")

	// End-to-end with the real detector.
	scanner := mailgun.Scanner{}
	results, err := scanner.FromData(context.AddLogger(context.Background()), false, emitted)
	require.NoError(t, err)
	found := make(map[string]bool)
	for _, r := range results {
		found[string(r.Raw)] = true
	}
	assert.True(t, found[pycMultiToken], "mailgun detector missed the token in multi-assignment .pyc")
}

// Unit test for the marshal string extraction used on Python bytecode.
func TestExtractPythonBytecodeStrings(t *testing.T) {
	in := []byte{
		0xcb, 0x0d, 0x0d, 0x0a, // pyc magic (noise)
		'z', 0x05, 'h', 'e', 'l', 'l', 'o', // short ascii
		0x00,
		0xda, 0x05, 'w', 'o', 'r', 'l', 'd', // ref-flagged short ascii interned
		's', 0x04, 0x00, 0x00, 0x00, 'b', 'y', 'e', 's', // bytes with 4-byte length
		'z', 0x02, 'a', 'b', // too short: dropped
		'z', 0xff, 'x', // length overruns buffer: dropped
		0x4e, // TYPE_NONE (noise)
	}
	assert.Equal(t, "byes\nworld\nhello", string(extractPythonBytecodeStrings(in)))
	assert.Empty(t, extractPythonBytecodeStrings([]byte("\x00\x01\x02")))
	assert.Empty(t, extractPythonBytecodeStrings(nil))
}

// Regression test for the review finding on PR #5434: marshal encodes sets
// as '<' and frozensets as '>' ('f' is the ASCII float code). Treating any
// other code as a set aborts the structural parse on frozenset constants
// and falls back to reverse order. A frozenset constant must parse cleanly
// and its string elements must be extracted.
func TestParseSetConstElem(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
		want string
	}{
		{"frozenset", "3e01000000fa15736b2d7365742d7365637265742d76616c75652d31", "sk-set-secret-value-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.hex)
			require.NoError(t, err)
			cur := &marshalCursor{data: raw}
			it, ok := cur.parseConstElem()
			require.True(t, ok, "set/frozenset constant failed to parse")
			require.True(t, cur.pos == len(raw), "trailing bytes after set constant")
			var spans []span
			collectItemSpans(it, &spans)
			var got []string
			for _, s := range spans {
				got = append(got, string(raw[s.start:s.end]))
			}
			assert.Contains(t, got, tc.want)
		})
	}
}

// Fixture: testdata/pyc_imports.pyc was compiled (CPython 3.12) from
//
//	import collections
//	import itertools
//	mailgun_imported = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
//
// The imports add leading entries to co_names with no matching co_consts
// entry. Pairing names and values by index puts the real keyword after its
// secret, so keyword-prefixed detectors miss it. The handler must emit
// every identifier before its code object's values.
func TestPythonBytecodeImportedModuleKeywordBeforeSecret(t *testing.T) {
	raw, err := os.ReadFile("testdata/pyc_imports.pyc")
	require.NoError(t, err)

	emitted := collectChunks(t, raw)
	require.NotEmpty(t, emitted, "expected .pyc content to produce chunks, got none")

	pattern := regexp.MustCompile(detectors.PrefixRegex([]string{"mailgun"}) + `\b([a-f0-9]{72})\b`)
	var secrets []string
	for _, m := range pattern.FindAllStringSubmatch(string(emitted), -1) {
		secrets = append(secrets, m[1])
	}
	const token = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
	require.NotEmpty(t, secrets, "prefix detector missed the secret in import-leading .pyc output")
	assert.Contains(t, secrets, token)

	kwIdx := bytes.Index(emitted, []byte("mailgun_imported"))
	secIdx := bytes.Index(emitted, []byte(token))
	require.NotEqual(t, -1, kwIdx)
	require.NotEqual(t, -1, secIdx)
	require.Less(t, kwIdx, secIdx, "keyword must precede the secret in handler output")
	assert.Less(t, secIdx-kwIdx, 40, "keyword/secret gap must fit PrefixRegex's window")
}
