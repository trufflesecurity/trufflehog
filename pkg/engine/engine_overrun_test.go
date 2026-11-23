package engine

import (
	aCtx "context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Fakes and log capture for the timeout-overrun metrics in detectChunk. The overrun test changes the
// package-global detectionTimeout, so neither test here may use t.Parallel(), and the overrun test must restore the
// previous value before returning.

const (
	slowOverrunKeyword   = "slowoverruntest"
	fastNoOverrunKeyword = "fastnooverruntest"
)

// slowOverrunDetector ignores its context on purpose: it sleeps past the detection timeout plus the one-second
// grace, which is the behavior the overrun metrics exist to observe. With the test's 10ms timeout the timer fires
// at about 1.01s and the sleep ends at 2s, so the callback always runs while FromData is still sleeping, with
// about a second of margin for CI scheduling jitter.
type slowOverrunDetector struct{}

var _ detectors.Detector = (*slowOverrunDetector)(nil)
var _ detectors.Versioner = (*slowOverrunDetector)(nil)

func (f slowOverrunDetector) FromData(_ aCtx.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	time.Sleep(2 * time.Second)
	return nil, nil
}

func (f slowOverrunDetector) Keywords() []string { return []string{slowOverrunKeyword} }

func (f slowOverrunDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Test
}

func (f slowOverrunDetector) Version() int { return 1 }

func (f slowOverrunDetector) Description() string { return "slow detector for overrun tests" }

// fastNoOverrunDetector returns immediately and stays well inside the default detection timeout.
type fastNoOverrunDetector struct{}

var _ detectors.Detector = (*fastNoOverrunDetector)(nil)
var _ detectors.Versioner = (*fastNoOverrunDetector)(nil)

func (f fastNoOverrunDetector) FromData(_ aCtx.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return nil, nil
}

func (f fastNoOverrunDetector) Keywords() []string { return []string{fastNoOverrunKeyword} }

func (f fastNoOverrunDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_TestingBot
}

func (f fastNoOverrunDetector) Version() int { return 1 }

func (f fastNoOverrunDetector) Description() string { return "fast detector for overrun tests" }

// logRecord is one entry captured by capturingLogSink.
type logRecord struct {
	msg   string
	level int
	isErr bool
	kv    []any
}

// hasField reports whether the entry carries a key of the given name.
func (r logRecord) hasField(key string) bool {
	for i := 0; i+1 < len(r.kv); i += 2 {
		if r.kv[i] == key {
			return true
		}
	}
	return false
}

// capturingLogSink records every entry a context logger emits so tests can assert on specific log lines. It
// reports every level as enabled and ignores the WithName/WithValues decorations, which the assertions do not
// need.
type capturingLogSink struct {
	mu      sync.Mutex
	records []logRecord
}

func (s *capturingLogSink) Init(_ logr.RuntimeInfo) {}

func (s *capturingLogSink) Enabled(_ int) bool { return true }

func (s *capturingLogSink) WithName(_ string) logr.LogSink { return s }

func (s *capturingLogSink) WithValues(_ ...any) logr.LogSink { return s }

func (s *capturingLogSink) Info(level int, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, logRecord{msg: msg, level: level, kv: keysAndValues})
}

func (s *capturingLogSink) Error(_ error, msg string, keysAndValues ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, logRecord{msg: msg, isErr: true, kv: keysAndValues})
}

// find returns the first entry captured with the given message.
func (s *capturingLogSink) find(msg string) (logRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.msg == msg {
			return r, true
		}
	}
	return logRecord{}, false
}

// TestEngine_DetectorOverrunsTimeout drives the overrun path end to end: a detector that keeps running past the
// detection timeout plus its one-second grace trips the timer callback (counter up, gauge up, Error log), and its
// return path brings the gauge back down, records the overrun duration, and logs the total hold time at V(2).
func TestEngine_DetectorOverrunsTimeout(t *testing.T) {
	previousTimeout := detectionTimeout
	SetDetectorTimeout(10 * time.Millisecond)
	defer SetDetectorTimeout(previousTimeout)

	sink := &capturingLogSink{}
	ctx, cancel := context.WithTimeout(context.WithLogger(context.Background(), logr.New(sink)), time.Minute)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "engineoverrun")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()
	_, err = fmt.Fprintf(tmpFile, "test data using keyword %s", slowOverrunKeyword)
	require.NoError(t, err)

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}
	sourceManager := sources.NewManager(opts...)

	conf := Config{
		Concurrency:   1,
		Decoders:      decoders.DefaultDecoders(),
		Detectors:     []detectors.Detector{new(slowOverrunDetector)},
		Verify:        false,
		SourceManager: sourceManager,
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}
	e, err := NewEngine(ctx, &conf)
	require.NoError(t, err)

	e.Start(ctx)

	scanDone := make(chan error, 1)
	go func() {
		_, err := e.ScanFileSystem(ctx, sources.FilesystemConfig{Paths: []string{tmpFile.Name()}})
		if err != nil {
			scanDone <- err
			return
		}
		scanDone <- e.Finish(ctx)
	}()

	label := detector_typepb.DetectorType_Test.String()
	assert.Eventually(t, func() bool {
		return testutil.ToFloat64(detectorWorkersOverTimeout.WithLabelValues(label)) == 1
	}, 10*time.Second, 10*time.Millisecond,
		"gauge should read 1 while the slow detector is still inside FromData")

	assert.NoError(t, <-scanDone)

	assert.Equal(t, float64(1), testutil.ToFloat64(detectorTimeoutIgnoredTotal.WithLabelValues(label)))
	assert.Equal(t, float64(0), testutil.ToFloat64(detectorWorkersOverTimeout.WithLabelValues(label)))
	assert.Equal(t, 1, testutil.CollectAndCount(detectorOverrunDuration),
		"the overrun histogram should have exactly the one series for this detector")

	// The callback closes fired before it logs, and the return path waits only for the close, so the fire line
	// can land after the scan has finished; the return line is emitted on the return path itself and is ordered
	// by <-scanDone.
	assert.Eventually(t, func() bool {
		fireLine, found := sink.find("a detector ignored the context timeout")
		return found && fireLine.isErr
	}, 5*time.Second, 10*time.Millisecond, "the timer firing should log at Error level")

	returnLine, found := sink.find("detector returned after overrunning the context timeout")
	assert.True(t, found, "the return path should log")
	assert.False(t, returnLine.isErr)
	assert.Equal(t, 2, returnLine.level, "the return log line should be at V(2)")
	assert.True(t, returnLine.hasField("duration"), "the return log line should carry a duration field")
}

// TestEngine_DetectorWithinTimeout drives the normal path: a detector that returns inside the detection timeout
// leaves every overrun metric untouched.
func TestEngine_DetectorWithinTimeout(t *testing.T) {
	sink := &capturingLogSink{}
	ctx, cancel := context.WithTimeout(context.WithLogger(context.Background(), logr.New(sink)), time.Minute)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "enginenooverrun")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()
	_, err = fmt.Fprintf(tmpFile, "test data using keyword %s", fastNoOverrunKeyword)
	require.NoError(t, err)

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}
	sourceManager := sources.NewManager(opts...)

	conf := Config{
		Concurrency:   1,
		Decoders:      decoders.DefaultDecoders(),
		Detectors:     []detectors.Detector{new(fastNoOverrunDetector)},
		Verify:        false,
		SourceManager: sourceManager,
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}
	e, err := NewEngine(ctx, &conf)
	require.NoError(t, err)

	e.Start(ctx)

	_, err = e.ScanFileSystem(ctx, sources.FilesystemConfig{Paths: []string{tmpFile.Name()}})
	require.NoError(t, err)
	require.NoError(t, e.Finish(ctx))

	label := detector_typepb.DetectorType_TestingBot.String()
	assert.Equal(t, float64(0), testutil.ToFloat64(detectorTimeoutIgnoredTotal.WithLabelValues(label)))
	assert.Equal(t, float64(0), testutil.ToFloat64(detectorWorkersOverTimeout.WithLabelValues(label)))
}
