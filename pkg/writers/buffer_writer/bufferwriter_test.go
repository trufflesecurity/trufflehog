package bufferwriter

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestBufferWriterWrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		input         []byte
		initialState  state
		expectedError bool
		expectedSize  int
	}{
		{
			name:         "Write in writeOnly state with empty input",
			input:        []byte(""),
			initialState: writeOnly,
		},
		{
			name:          "Write in writeOnly state with non-empty input",
			input:         []byte("hello"),
			initialState:  writeOnly,
			expectedError: false,
			expectedSize:  5,
		},
		{
			name:          "Attempt to write in readOnly state",
			input:         []byte("hello"),
			initialState:  readOnly,
			expectedError: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New()
			writer.state = tc.initialState

			_, err := writer.Write(tc.input)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedSize, writer.Len())
			}
		})
	}
}

func TestBufferWriterReadCloser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		initialState  state
		expectedError bool
	}{
		{
			name:          "Get ReadCloser in writeOnly state",
			initialState:  writeOnly,
			expectedError: true,
		},
		{
			name:         "Get ReadCloser in readOnly state",
			initialState: readOnly,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New()
			writer.state = tc.initialState
			writer.buf = writer.bufPool.Get()

			rc, err := writer.ReadCloser()
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, rc)

				// Test that the ReadCloser can be closed.
				err = rc.Close()
				assert.NoError(t, err)
			}
		})
	}
}

func TestBufferWriterCloseForWriting(t *testing.T) {
	writer := New()
	err := writer.CloseForWriting()
	assert.NoError(t, err)
	assert.Equal(t, readOnly, writer.state)
}

func TestBufferWriterString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		prepareBuffer func(*BufferWriter) // Function to prepare the buffer with data or state
		expectedStr   string
		expectedError bool
	}{
		{
			name: "String with no data",
			prepareBuffer: func(bw *BufferWriter) {
				_, _ = bw.Write([]byte(""))
			},
			expectedStr:   "",
			expectedError: false,
		},
		{
			name: "String with data",
			prepareBuffer: func(bw *BufferWriter) {
				_, _ = bw.Write([]byte("test data"))
			},
			expectedStr:   "test data",
			expectedError: false,
		},
		{
			name: "Buffer is nil",
			prepareBuffer: func(bw *BufferWriter) {
				bw.buf = nil
			},
			expectedStr:   "",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			writer := New()
			tc.prepareBuffer(writer)

			result, err := writer.String()
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedStr, result)
			}
		})
	}
}

// Create a custom reader that can simulate errors.
type errorReader struct{}

func (errorReader) Read([]byte) (n int, err error) { return 0, fmt.Errorf("error reading") }

func TestNewFromReader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		reader   io.Reader
		wantErr  bool
		wantData string
	}{
		{
			name:     "Success case",
			reader:   strings.NewReader("hello world"),
			wantData: "hello world",
		},
		{
			name:   "Empty reader",
			reader: strings.NewReader(""),
		},
		{
			name:    "Error reader",
			reader:  errorReader{},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			bufWriter, err := NewFromReader(ctx, tc.reader)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, bufWriter)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, bufWriter)

			err = bufWriter.CloseForWriting()
			assert.NoError(t, err)

			buffer := new(bytes.Buffer)
			rdr, err := bufWriter.ReadCloser()
			assert.NoError(t, err)
			defer rdr.Close()

			_, err = buffer.ReadFrom(rdr)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantData, buffer.String())
		})
	}
}
