package handlers

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"time"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/go-logr/logr"
	"github.com/h2non/filetype"
	"golang.org/x/sync/semaphore"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Tika is a handler that uses Apache Tika to extract text from many file types.
type tika struct {
	enabled     bool
	logger      logr.Logger
	endpoint    string
	ocrTimeout  string
	client      *http.Client
	concurrency *semaphore.Weighted
	disableOCR  bool
}

func WithLogger(log logr.Logger) func(*tika) {
	return func(t *tika) {
		t.logger = log
	}
}

func WithEndpoint(endpoint string) func(*tika) {
	return func(t *tika) {
		t.endpoint = endpoint
	}
}

func WithOCRTimeout(timeoutSeconds int) func(*tika) {
	return func(t *tika) {
		t.ocrTimeout = fmt.Sprintf("%d", timeoutSeconds)
	}
}

func WithDisableOCR(disable bool) func(*tika) {
	return func(t *tika) {
		t.disableOCR = disable
	}
}

func WithHTTPClient(client *http.Client) func(*tika) {
	return func(t *tika) {
		t.client = client
	}
}

func WithConcurrency(concurrency int64) func(*tika) {
	return func(t *tika) {
		t.concurrency = semaphore.NewWeighted(concurrency)
	}
}

// New creates a new Tika handler.
func NewTika(opts ...func(*tika)) *tika {
	transport := http.Transport{
		Dial: func(netword, addr string) (net.Conn, error) {
			return net.DialTimeout(netword, addr, 1*time.Second)
		},
	}

	client := http.Client{
		Transport: &transport,
	}

	t := &tika{
		logger:      context.Background().Logger().WithValues("component", "tika_handler"),
		endpoint:    "http://localhost:9998/tika",
		ocrTimeout:  "20",
		client:      &client,
		concurrency: semaphore.NewWeighted(int64(runtime.NumCPU())),
	}

	for _, opt := range opts {
		opt(t)
	}

	req, err := http.NewRequest("GET", t.endpoint, nil)
	if err != nil {
		t.logger.Error(err, "Invalid URL for Tika server, disabling file handler")
		return nil
	}
	res, err := common.SaneHttpClient().Do(req)
	if err != nil {
		t.logger.Error(err, "Failed to test connection to Tika server, disabling file handler")
		return nil
	}
	if res.StatusCode != 200 {
		t.logger.Error(err, "Failed to test connection to Tika server (invalid response), disabling file handler")
	}

	return t
}

func (t *tika) New() {}

// IsFiletype returns true if the file is a supported filetype.
func (t *tika) IsFiletype(file *diskbufferreader.DiskBufferReader) bool {
	// We only have to pass the file header = first 261 bytes
	head := make([]byte, 261)
	n, err := file.Read(head)
	if n < 261 || err != nil {
		return false
	}

	switch {
	case filetype.IsMIME(head, "image/jpeg"):
		return true
	case filetype.IsMIME(head, "image/png"):
		return true
	case filetype.IsMIME(head, "image/bmp"):
		return true
	case filetype.IsMIME(head, "image/tiff"):
		return true
	case filetype.IsMIME(head, "image/gif"):
		return true
	case filetype.IsDocument(head):
		return true
	case filetype.IsMIME(head, "application/pdf"):
		return true
	case filetype.IsMIME(head, "application/rtf"):
		return true
	default:
		return false

		// TODO: add open office identification
	}
}

// FromFile returns a channel of []byte chunks from the file.
func (t *tika) FromFile(file *diskbufferreader.DiskBufferReader) chan ([]byte) {
	t.concurrency.Acquire(context.Background(), 1)

	outputChan := make(chan []byte)

	go func() {
		defer t.concurrency.Release(1)

		t.logger.V(1).Info("Extracting text from file using Apache Tika")
		req, err := http.NewRequest("PUT", t.endpoint, file)
		if err != nil {
			t.logger.Error(err, "Failed to create request for tika server")
			return
		}
		req.Header.Set("X-Tika-OCRTimeoutSeconds", t.ocrTimeout)
		if t.disableOCR {
			req.Header.Set("X-Tika-OCRmaxFileSizeToOcr", "0")
		}
		req.Header.Set("Accept", "text/plain")

		resp, err := t.client.Do(req)
		if err != nil {
			t.logger.Error(err, "Failed to send request to tika server")
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.logger.Error(err, "Failed to read response from tika server")
			return
		}

		outputChan <- body
		close(outputChan)
	}()

	return outputChan
}
