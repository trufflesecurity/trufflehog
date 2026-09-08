// Package httpx scans the JSONL output produced by ProjectDiscovery's httpx
// (https://github.com/projectdiscovery/httpx) when it is run with response
// capture enabled, e.g.
//
//	httpx -l hosts.txt -json -irr -o responses.jsonl
//
// Only the response body fields are scanned. Every other field in the record
// (raw_header, header, request, title, tech, chain, knowledgebase, ...) is used
// for metadata at most and is never handed to the detector engine. This keeps
// scans focused on server-returned content and avoids the large volume of false
// positives that header and request echoes produce.
//
// The reader is fully streaming: records are read one newline-delimited line at
// a time out of a buffered reader and dispatched to a bounded worker pool, so a
// multi-gigabyte JSONL file with hundreds of thousands of records is processed
// with memory proportional to (workers x largest record) rather than to file
// size.
package httpx

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_HTTPX

const (
	// readBufferSize is the size of the buffered reader sitting in front of the
	// JSONL file. httpx records containing a response body are routinely tens or
	// hundreds of kilobytes, so a large buffer meaningfully cuts syscall count on
	// big files.
	readBufferSize = 1 << 20 // 1 MiB

	// DefaultMaxRecordBytes is the default ceiling on a single JSONL record.
	// Records larger than this are skipped (with a log line) rather than
	// buffered, which bounds worst-case memory when a scan hits a pathological
	// response.
	DefaultMaxRecordBytes = 64 << 20 // 64 MiB

	// progressInterval is how many records are processed between progress
	// updates. Updating on every record would dominate the scan with lock
	// traffic on very large files.
	progressInterval = 5_000

	// stdinPath is the path value that means "read the JSONL stream from stdin".
	stdinPath = "-"
)

// errRecordTooLong is returned by lineReader when a record exceeds maxRecordBytes.
var errRecordTooLong = errors.New("record exceeds maximum record size")

// Source scans httpx JSONL output for secrets in HTTP response bodies.
type Source struct {
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	concurrency int

	paths               []string
	base64Body          bool
	includeHeadlessBody bool
	maxRecordBytes      int64

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType { return SourceType }
func (s *Source) SourceID() sources.SourceID { return s.sourceId }
func (s *Source) JobID() sources.JobID       { return s.jobId }

func (s *Source) Init(
	_ context.Context,
	name string,
	jobId sources.JobID,
	sourceId sources.SourceID,
	verify bool,
	connection *anypb.Any,
	concurrency int,
) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.concurrency = concurrency

	var conn sourcespb.Httpx
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	s.paths = conn.GetPaths()
	s.base64Body = conn.GetBase64Body()
	s.includeHeadlessBody = conn.GetIncludeHeadlessBody()

	s.maxRecordBytes = conn.GetMaxRecordBytes()
	if s.maxRecordBytes <= 0 {
		s.maxRecordBytes = DefaultMaxRecordBytes
	}

	if len(s.paths) == 0 {
		return errors.New("no httpx JSONL paths provided")
	}

	return nil
}

// workers returns the size of the record-processing pool.
func (s *Source) workers() int {
	if s.concurrency > 0 {
		return s.concurrency
	}
	return 1
}

func (s *Source) Chunks(
	ctx context.Context,
	chunksChan chan *sources.Chunk,
	_ ...sources.ChunkingTarget,
) error {
	// Progress is tracked in KiB rather than files or records: a scan is usually
	// a single very large file, so file-granular progress would sit at 0% for the
	// entire run. KiB (rather than bytes) keeps the counters inside int32.
	// A total of zero means at least one input has no knowable size (stdin or a
	// pipe); fall back to counting files so progress never divides by zero.
	totalKiB := totalSizeKiB(s.paths)
	byteProgress := totalKiB > 0
	var doneKiB int64

	for i, path := range s.paths {
		if common.IsDone(ctx) {
			return nil
		}

		fileCtx := context.WithValues(ctx, "file", path)
		read, err := s.scanFile(fileCtx, path, chunksChan, doneKiB, totalKiB)
		doneKiB += read / 1024
		if err != nil {
			// A failure on one input file should not abort the remaining files.
			fileCtx.Logger().Error(err, "error scanning httpx JSONL file")
		}

		msg := fmt.Sprintf("Path: %s", path)
		if byteProgress {
			s.SetProgressComplete(int(doneKiB), int(totalKiB), msg, "")
		} else {
			s.SetProgressComplete(i+1, len(s.paths), msg, "")
		}
	}

	return nil
}

// totalSizeKiB sums the on-disk size of the given paths, in KiB. Paths whose
// size cannot be determined (stdin, pipes, missing files) contribute zero.
func totalSizeKiB(paths []string) int64 {
	var total int64
	for _, p := range paths {
		if p == stdinPath {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			total += info.Size() / 1024
		}
	}
	return total
}

// scanFile opens path (or stdin) and scans it, returning the number of
// compressed/on-disk bytes consumed.
func (s *Source) scanFile(
	ctx context.Context,
	path string,
	chunksChan chan *sources.Chunk,
	baseKiB, totalKiB int64,
) (int64, error) {
	var raw io.Reader

	if path == stdinPath {
		raw = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return 0, fmt.Errorf("unable to open file: %w", err)
		}
		defer func() { _ = f.Close() }()
		raw = f
	}

	// Count bytes at the outermost layer so progress reflects file position even
	// when the input is gzipped.
	counter := &countingReader{r: raw}

	reader, closeFn, err := maybeDecompress(counter)
	if err != nil {
		return counter.Count(), err
	}
	defer closeFn()

	// Only report byte-granular progress when the total size is known.
	var progress func(records int64)
	if totalKiB > 0 {
		progress = func(records int64) {
			kib := baseKiB + counter.Count()/1024
			s.SetProgressComplete(
				int(kib), int(totalKiB),
				fmt.Sprintf("Path: %s (%d records)", path, records), "",
			)
		}
	}

	ctx.Logger().V(3).Info("scanning httpx JSONL file")

	// Evaluate the scan first: `return counter.Count(), s.scanReader(...)` would
	// read the counter before the scan ran.
	scanErr := s.scanReader(ctx, reader, path, chunksChan, progress)
	return counter.Count(), scanErr
}

// maybeDecompress transparently unwraps a gzip stream. httpx output is
// frequently stored compressed, and a 1 GiB JSONL file typically shrinks by an
// order of magnitude.
func maybeDecompress(r io.Reader) (io.Reader, func(), error) {
	br := bufio.NewReaderSize(r, readBufferSize)

	magic, err := br.Peek(2)
	if err != nil || len(magic) < 2 || magic[0] != 0x1f || magic[1] != 0x8b {
		// Not gzip (or too small to tell); read it as-is.
		return br, func() {}, nil
	}

	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, func() {}, fmt.Errorf("unable to open gzip stream: %w", err)
	}
	return bufio.NewReaderSize(gz, readBufferSize), func() { _ = gz.Close() }, nil
}

// scanReader consumes a JSONL stream and emits chunks for every response body
// it finds. Records are read serially (cheap) and unmarshalled/chunked in
// parallel (expensive), which keeps a single reader goroutine from becoming the
// bottleneck on large files.
func (s *Source) scanReader(
	ctx context.Context,
	r io.Reader,
	file string,
	chunksChan chan *sources.Chunk,
	progress func(records int64),
) error {
	reporter := sources.ChanReporter{Ch: chunksChan}
	lines := newLineReader(r, s.recordLimit())

	type recordJob struct {
		line []byte
		num  int64
	}

	workers := s.workers()
	jobs := make(chan recordJob, workers*4)

	// stop is closed by the first worker to hit a fatal error so the reader
	// goroutine below does not block forever on a channel nobody is draining.
	stop := make(chan struct{})
	var stopOnce sync.Once

	var stats scanStats

	var pool errgroup.Group
	for i := 0; i < workers; i++ {
		pool.Go(func() error {
			for job := range jobs {
				if common.IsDone(ctx) {
					return ctx.Err()
				}
				if err := s.processRecord(ctx, job.line, file, job.num, reporter, &stats); err != nil {
					stopOnce.Do(func() { close(stop) })
					return err
				}
			}
			return nil
		})
	}

	var readErr error
	var lineNum int64

readLoop:
	for {
		if common.IsDone(ctx) {
			break
		}

		line, err := lines.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, errRecordTooLong) {
				lineNum++
				stats.skippedTooLong.Add(1)
				ctx.Logger().V(2).Info("skipping oversized httpx record",
					"line", lineNum, "limit_bytes", s.recordLimit())
				continue
			}
			readErr = fmt.Errorf("error reading httpx JSONL: %w", err)
			break
		}

		lineNum++
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		select {
		case jobs <- recordJob{line: line, num: lineNum}:
		case <-stop:
			break readLoop
		case <-ctx.Done():
			break readLoop
		}

		if progress != nil && lineNum%progressInterval == 0 {
			progress(lineNum)
		}
	}

	close(jobs)
	poolErr := pool.Wait()

	ctx.Logger().V(2).Info("finished httpx JSONL file",
		"records", lineNum,
		"bodies_scanned", stats.bodiesScanned.Load(),
		"records_without_body", stats.noBody.Load(),
		"records_malformed", stats.malformed.Load(),
		"records_too_long", stats.skippedTooLong.Load(),
	)

	if readErr != nil {
		return readErr
	}
	return poolErr
}

func (s *Source) recordLimit() int64 {
	if s.maxRecordBytes > 0 {
		return s.maxRecordBytes
	}
	return DefaultMaxRecordBytes
}

// scanStats holds per-file counters. Fields are atomic because they are
// incremented from the worker pool.
type scanStats struct {
	bodiesScanned  atomic.Int64
	noBody         atomic.Int64
	malformed      atomic.Int64
	skippedTooLong atomic.Int64
}

// httpxRecord is the subset of httpx's JSON output that this source cares
// about. Unknown fields are skipped by encoding/json rather than retained, so
// wide records (tls, chain, knowledgebase, screenshot_bytes, ...) do not inflate
// memory use.
//
// Body and HeadlessBody are pointers so that an explicit `null` and an absent
// field are both representable without being confused with an empty body.
type httpxRecord struct {
	URL          string  `json:"url"`
	FinalURL     string  `json:"final_url"`
	Input        string  `json:"input"`
	Host         string  `json:"host"`
	Path         string  `json:"path"`
	Method       string  `json:"method"`
	Scheme       string  `json:"scheme"`
	ContentType  string  `json:"content_type"`
	Timestamp    string  `json:"timestamp"`
	StatusCode   int32   `json:"status_code"`
	Body         *string `json:"body"`
	HeadlessBody *string `json:"headless_body"`
}

// location returns the best available URL for the record. httpx omits `url` for
// some failure modes, so fall back to the post-redirect URL and finally to the
// raw input line.
func (r *httpxRecord) location() string {
	switch {
	case r.URL != "":
		return r.URL
	case r.FinalURL != "":
		return r.FinalURL
	default:
		return r.Input
	}
}

// processRecord parses one JSONL record and hands each of its response bodies
// to the file handlers. A malformed record is logged and skipped: a single bad
// line (a truncated final record from an interrupted httpx run, for example)
// must not abort a scan of hundreds of thousands of records.
func (s *Source) processRecord(
	ctx context.Context,
	line []byte,
	file string,
	lineNum int64,
	reporter sources.ChunkReporter,
	stats *scanStats,
) error {
	var rec httpxRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		stats.malformed.Add(1)
		ctx.Logger().V(3).Info("skipping malformed httpx record", "line", lineNum, "error", err.Error())
		return nil
	}

	bodies := make([]bodyField, 0, 2)
	if rec.Body != nil && *rec.Body != "" {
		bodies = append(bodies, bodyField{name: "body", value: *rec.Body})
	}
	if s.includeHeadlessBody && rec.HeadlessBody != nil && *rec.HeadlessBody != "" {
		bodies = append(bodies, bodyField{name: "headless_body", value: *rec.HeadlessBody})
	}

	if len(bodies) == 0 {
		// Body was null, empty, or absent (httpx run without -irr / a failed request).
		stats.noBody.Add(1)
		return nil
	}

	for _, body := range bodies {
		data := []byte(body.value)
		if s.base64Body {
			decoded, err := base64.StdEncoding.DecodeString(body.value)
			if err != nil {
				// Fall back to the raw value: mixed-encoding files are more
				// useful scanned imperfectly than skipped entirely.
				ctx.Logger().V(3).Info("body is not valid base64, scanning raw",
					"line", lineNum, "field", body.name, "error", err.Error())
			} else {
				data = decoded
			}
		}

		chunkSkel := &sources.Chunk{
			SourceType:   s.Type(),
			SourceName:   s.name,
			SourceID:     s.SourceID(),
			JobID:        s.JobID(),
			SourceVerify: s.verify,
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Httpx{
					Httpx: &source_metadatapb.Httpx{
						Url:         rec.location(),
						FinalUrl:    rec.FinalURL,
						Input:       rec.Input,
						Host:        rec.Host,
						Path:        rec.Path,
						Method:      rec.Method,
						Scheme:      rec.Scheme,
						StatusCode:  rec.StatusCode,
						ContentType: rec.ContentType,
						Timestamp:   rec.Timestamp,
						File:        file,
						Line:        lineNum,
						BodyField:   body.name,
					},
				},
			},
		}

		if err := handlers.HandleFile(ctx, bytes.NewReader(data), chunkSkel, reporter); err != nil {
			if common.IsDone(ctx) {
				return ctx.Err()
			}
			ctx.Logger().Error(err, "failed to scan response body",
				"line", lineNum, "url", rec.location(), "field", body.name)
			continue
		}
		stats.bodiesScanned.Add(1)
	}

	return nil
}

type bodyField struct {
	name  string
	value string
}

// countingReader tracks how many bytes have been read from the underlying
// reader so scan progress can be reported against the file size.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

func (c *countingReader) Count() int64 { return c.n.Load() }

// lineReader yields newline-delimited records of arbitrary length while capping
// the memory any single record may consume.
//
// bufio.Scanner is deliberately not used here: it fails the whole stream once a
// token exceeds its buffer, which would silently truncate a scan the first time
// httpx captured an unusually large response. lineReader instead skips the
// oversized record and resynchronises on the next newline.
type lineReader struct {
	r       *bufio.Reader
	maxLine int64
}

func newLineReader(r io.Reader, maxLine int64) *lineReader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, readBufferSize)
	}
	return &lineReader{r: br, maxLine: maxLine}
}

// next returns the next record without its trailing newline. The returned slice
// is freshly allocated and owned by the caller, which makes it safe to hand off
// to the worker pool.
func (lr *lineReader) next() ([]byte, error) {
	var buf []byte

	for {
		frag, err := lr.r.ReadSlice('\n')

		if errors.Is(err, bufio.ErrBufferFull) {
			if int64(len(buf)+len(frag)) > lr.maxLine {
				return nil, lr.skipRest()
			}
			buf = append(buf, frag...)
			continue
		}

		if err != nil {
			if errors.Is(err, io.EOF) && len(buf)+len(frag) > 0 {
				// Final record with no trailing newline.
				if int64(len(buf)+len(frag)) > lr.maxLine {
					return nil, errRecordTooLong
				}
				return append(buf, dropCR(frag)...), nil
			}
			return nil, err
		}

		// frag ends in '\n'; the delimiter itself does not count toward the limit.
		if int64(len(buf)+len(frag)-1) > lr.maxLine {
			return nil, errRecordTooLong
		}
		return append(buf, dropCR(frag[:len(frag)-1])...), nil
	}
}

// skipRest discards the remainder of an oversized record so reading can resume
// at the next record boundary.
func (lr *lineReader) skipRest() error {
	for {
		_, err := lr.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return errRecordTooLong
	}
}

// dropCR removes a trailing carriage return, so CRLF-delimited files (a common
// result of moving output off a Windows host) parse correctly.
func dropCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}
