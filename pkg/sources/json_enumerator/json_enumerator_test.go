package json_enumerator

import (
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
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const secretPart1 string = "SECRET"
const secretPart2 string = "SPLIT"

// Split the secret into two parts and pad the rest of the chunk with A's.
func makeStringData(t *testing.T, chunkSize int) []byte {
	t.Helper()
	data := []byte(strings.Repeat("A", chunkSize-len(secretPart1)) + secretPart1 + secretPart2 + strings.Repeat("A", chunkSize-len(secretPart2)))
	assert.True(t, utf8.Valid(data))
	return data
}

// Split the secret into two parts and pad the rest of the chunk with invalid unicode
func makeBase64Data(t *testing.T, chunkSize int) []byte {
	t.Helper()
	data := []byte(strings.Repeat("\xff", chunkSize-len(secretPart1)) + secretPart1 + secretPart2 + strings.Repeat("\xf0", chunkSize-len(secretPart2)))
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
			require.NoError(t, enc.Encode(&jsonEntry{Data: testCase.data, Metadata: testCase.metadata}))
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
