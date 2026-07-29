package json_enumerator

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const secretPart1 string = "SECRET"
const secretPart2 string = "SPLIT"

// Split the secret into two parts and pad the rest of the chunk with A's.
func makeStringData(t *testing.T, chunkSize int) []byte {
	t.Helper()
	data := []byte(strings.Join([]string{
		strings.Repeat("A", chunkSize-len(secretPart1)),
		secretPart1,
		secretPart2,
		strings.Repeat("A", chunkSize-len(secretPart2)),
	}, ""))
	assert.True(t, utf8.Valid(data))
	return data
}

// Split the secret into two parts and pad the rest of the chunk with invalid unicode
func makeBase64Data(t *testing.T, chunkSize int) []byte {
	t.Helper()
	data := []byte(strings.Join([]string{
		strings.Repeat("\xff", chunkSize-len(secretPart1)),
		secretPart1,
		secretPart2,
		strings.Repeat("\xf0", chunkSize-len(secretPart2)),
	}, ""))
	assert.False(t, utf8.Valid(data))
	return data
}

func makeRawMessage(t *testing.T, payload string) json.RawMessage {
	t.Helper()
	var m json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(payload), &m))
	return m
}

func TestScanEnumerator(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		data       []byte
		metadata   json.RawMessage
		shouldFail bool
	}{
		{
			name:       "bad metadata 1",
			data:       makeStringData(t, 30),
			metadata:   makeRawMessage(t, "null"),
			shouldFail: true,
		},
		{
			name:     "small string",
			data:     makeStringData(t, 30),
			metadata: makeRawMessage(t, "{}"),
		},
		{
			name:     "small bytestring",
			data:     makeBase64Data(t, 30),
			metadata: makeRawMessage(t, "{}"),
		},
		{
			name:     "big string",
			data:     makeStringData(t, sources.DefaultChunkSize*10),
			metadata: makeRawMessage(t, "{}"),
		},
		{
			name:     "big bytestring",
			data:     makeBase64Data(t, sources.DefaultChunkSize*10),
			metadata: makeRawMessage(t, "{}"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			readJSON, writeJSON := io.Pipe()

			chunksChan := make(chan *sources.Chunk, 2)
			var workerError error
			var wg sync.WaitGroup
			wg.Add(1)

			go func() {
				defer wg.Done()
				defer close(chunksChan)
				ctx := context.WithLogger(t.Context(), logr.Discard())
				source := &Source{}
				workerError = source.chunkJSONEnumeratorReader(ctx, readJSON, chunksChan)
			}()

			enc := json.NewEncoder(writeJSON)
			require.NoError(t, enc.Encode(&jsonEntry{
				Data:     testCase.data,
				Metadata: testCase.metadata,
			}))
			require.NoError(t, writeJSON.Close())

			foundSecret := ""
			for chunk := range chunksChan {
				foundSecret += string(chunk.Data)
			}

			wg.Wait()
			if testCase.shouldFail {
				require.Error(t, workerError)
			} else {
				require.NoError(t, workerError)
				assert.Contains(t, foundSecret, secretPart1+secretPart2)
			}
		})
	}
}

// makeZip builds an in-memory zip from the given entries. A large stored padding
// entry is written first so mimetype classifies the bytes as a generic zip,
// leaving APK identification to the content-based deep scan.
func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	padding, err := zw.CreateHeader(&zip.FileHeader{Name: "padding.txt", Method: zip.Store})
	require.NoError(t, err)
	_, err = padding.Write(bytes.Repeat([]byte("A"), 5000))
	require.NoError(t, err)

	for name, content := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// TestScanEnumeratorAPKContentRouting proves json-enumerator input is routed by
// file content, not by any filename/extension. The records carry no filename.
// A zip whose contents mark it as an APK (AndroidManifest.xml + classes.dex) is
// routed to the APK handler; because this synthetic archive lacks resources.arsc
// the APK handler yields no chunks, so the plaintext secret is not surfaced.
// The identical secret in a plain zip (no APK markers) is handled generically
// and surfaces the secret.
func TestScanEnumeratorAPKContentRouting(t *testing.T) {
	feature.EnableAPKHandler.Store(true)
	t.Cleanup(func() { feature.EnableAPKHandler.Store(false) })

	secret := secretPart1 + secretPart2

	apkZip := makeZip(t, map[string]string{
		"AndroidManifest.xml": "placeholder",
		"classes.dex":         "placeholder",
		"assets/secret.txt":   secret,
	})
	plainZip := makeZip(t, map[string]string{
		"assets/secret.txt": secret,
	})

	run := func(data []byte) (string, error) {
		readJSON, writeJSON := io.Pipe()
		chunksChan := make(chan *sources.Chunk, 16)

		var workerError error
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(chunksChan)
			ctx := context.WithLogger(t.Context(), logr.Discard())
			source := &Source{}
			workerError = source.chunkJSONEnumeratorReader(ctx, readJSON, chunksChan)
		}()

		// No filename is set on the record; routing is content-based only.
		enc := json.NewEncoder(writeJSON)
		require.NoError(t, enc.Encode(&jsonEntry{Metadata: makeRawMessage(t, "{}"), Data: data}))
		require.NoError(t, writeJSON.Close())

		found := ""
		for chunk := range chunksChan {
			found += string(chunk.Data)
		}
		wg.Wait()
		return found, workerError
	}

	foundAPK, err := run(apkZip)
	require.NoError(t, err)
	assert.NotContains(t, foundAPK, secret, "APK-content archive should be routed to the APK handler")

	foundZip, err := run(plainZip)
	require.NoError(t, err)
	assert.Contains(t, foundZip, secret, "non-APK zip should be handled generically and surface the secret")
}
