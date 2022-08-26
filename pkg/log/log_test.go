package log

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNew(t *testing.T) {
	var jsonBuffer, consoleBuffer bytes.Buffer
	logger, flush := New("service-name",
		WithJSONSink(&jsonBuffer),
		WithConsoleSink(&consoleBuffer),
	)
	logger.Info("yay")
	assert.Nil(t, flush())

	var parsedJSON map[string]any
	assert.Nil(t, json.Unmarshal(jsonBuffer.Bytes(), &parsedJSON))
	assert.NotEmpty(t, parsedJSON["ts"])
	delete(parsedJSON, "ts")
	assert.Equal(t,
		map[string]any{
			"level":  "info-0",
			"logger": "service-name",
			"msg":    "yay",
		},
		parsedJSON,
	)
	assert.Equal(t,
		[]string{"info-0\tservice-name\tyay"},
		splitLines(consoleBuffer.String()),
	)
}

func TestSetLevel(t *testing.T) {
	var buffer bytes.Buffer
	defer SetLevel(0)
	logger, _ := New("service-name", WithConsoleSink(&buffer))

	assert.Equal(t, true, logger.GetSink().Enabled(0))
	assert.Equal(t, false, logger.GetSink().Enabled(1))
	assert.Equal(t, false, logger.GetSink().Enabled(2))

	SetLevel(1)
	assert.Equal(t, true, logger.GetSink().Enabled(0))
	assert.Equal(t, true, logger.GetSink().Enabled(1))
	assert.Equal(t, false, logger.GetSink().Enabled(2))

	SetLevel(2)
	assert.Equal(t, true, logger.GetSink().Enabled(0))
	assert.Equal(t, true, logger.GetSink().Enabled(1))
	assert.Equal(t, true, logger.GetSink().Enabled(2))
}

func TestWithSentryFailure(t *testing.T) {
	var buffer bytes.Buffer
	logger, flush := New("service-name",
		WithSentry(sentry.ClientOptions{Dsn: "fail"}, nil),
		WithConsoleSink(&buffer),
	)
	logger.Info("yay")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "error configuring logger")
	assert.Contains(t, buffer.String(), "yay")
}

func TestAddSentryFailure(t *testing.T) {
	var buffer bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buffer))
	logger, _, err := AddSentry(logger, sentry.ClientOptions{Dsn: "fail"}, nil)
	assert.NotNil(t, err)
	assert.NotContains(t, err.Error(), "unsupported")

	logger.Info("yay")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "yay")
}

func TestAddSentry(t *testing.T) {
	var buffer bytes.Buffer
	var sentryMessage string
	logger, _ := New("service-name", WithConsoleSink(&buffer))
	logger, flush, err := AddSentry(logger, sentry.ClientOptions{
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			sentryMessage = event.Message
			return nil
		},
	}, nil)
	assert.Nil(t, err)

	logger.Error(nil, "oops")
	logger.Info("yay")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "oops")
	assert.Contains(t, buffer.String(), "yay")
	assert.Equal(t, "oops", sentryMessage)
}

func TestWithSentry(t *testing.T) {
	var buffer bytes.Buffer
	var sentryMessage string
	logger, flush := New("service-name",
		WithConsoleSink(&buffer),
		WithSentry(sentry.ClientOptions{
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				sentryMessage = event.Message
				return nil
			},
		}, nil),
	)
	logger.Info("yay")
	logger.Error(nil, "oops")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "yay")
	assert.Contains(t, buffer.String(), "oops")
	assert.Equal(t, "oops", sentryMessage)
}

func TestHumanReadableTimestamp(t *testing.T) {
	var buffer bytes.Buffer
	logger, flush := New("service-name",
		WithConsoleSink(&buffer),
	)
	logger.Info("yay")
	assert.Nil(t, flush())

	ts := strings.Split(buffer.String(), "\t")[0]
	assert.NotContains(t, ts, "e+09")

	parsedTime, err := time.Parse(time.RFC3339, ts)
	assert.Nil(t, err)
	assert.Less(t, time.Since(parsedTime), 5*time.Second)
}

func TestAddSink(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger, _ := New("service-name",
		WithConsoleSink(&buf1),
	)
	logger.Info("line 1")
	logger, flush, err := AddSink(logger, WithConsoleSink(&buf2))
	assert.Nil(t, err)
	logger.Info("line 2")
	assert.Nil(t, flush())

	assert.Contains(t, buf1.String(), "line 1")
	assert.Contains(t, buf1.String(), "line 2")
	// buf2 should only have "line 2"
	assert.NotContains(t, buf2.String(), "line 1")
	assert.Contains(t, buf2.String(), "line 2")
}

func TestStaticLevelSink(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	l1 := zap.NewAtomicLevel()
	logger, flush := New(
		"service-name",
		WithConsoleSink(&buf1, WithLeveler(l1)),
		WithConsoleSink(&buf2, WithLevel(0)),
	)

	logger.Info("line 1")
	SetLevelForControl(l1, 1)
	logger.V(1).Info("line 2")
	assert.Nil(t, flush())

	// buf1 should have both lines
	assert.Contains(t, buf1.String(), "line 1")
	assert.Contains(t, buf1.String(), "line 2")

	// buf2 should only have "line 1"
	assert.Contains(t, buf2.String(), "line 1")
	assert.NotContains(t, buf2.String(), "line 2")
}

func TestWithLeveler(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	l1, l2 := zap.NewAtomicLevel(), zap.NewAtomicLevel()
	logger, flush := New(
		"service-name",
		WithConsoleSink(&buf1, WithLeveler(l1)),
		WithConsoleSink(&buf2, WithLeveler(l2)),
	)

	SetLevelForControl(l1, 1)
	SetLevelForControl(l2, 2)

	logger.V(0).Info("line 1")
	logger.V(1).Info("line 2")
	logger.V(2).Info("line 3")
	assert.Nil(t, flush())

	// buf1 should have lines 1 and 2
	assert.Contains(t, buf1.String(), "line 1")
	assert.Contains(t, buf1.String(), "line 2")
	assert.NotContains(t, buf1.String(), "line 3")

	// buf2 should have all lines
	assert.Contains(t, buf2.String(), "line 1")
	assert.Contains(t, buf2.String(), "line 2")
	assert.Contains(t, buf2.String(), "line 3")
}

func TestWithNamedLevelMoreVerbose(t *testing.T) {
	var buf bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	l1 := zap.NewAtomicLevel()
	logger, flush := New(
		"service-name",
		WithConsoleSink(&buf, WithLeveler(l1)),
	)

	childLogger := WithNamedLevel(logger, "child")

	SetLevelForControl(l1, 1)
	SetLevelFor("child", 2)

	logger.V(0).Info("line 1")
	logger.V(1).Info("line 2")
	logger.V(2).Info("line 3")
	childLogger.V(0).Info("line A")
	childLogger.V(1).Info("line B")
	childLogger.V(2).Info("line C")
	assert.Nil(t, flush())

	// output should contain up to verbosity 1
	assert.Equal(t, []string{
		"info-0\tservice-name\tline 1",
		"info-1\tservice-name\tline 2",
		"info-0\tservice-name.child\tline A",
		"info-1\tservice-name.child\tline B",
	}, splitLines(buf.String()))
}

func TestWithNamedLevelLessVerbose(t *testing.T) {
	var buf bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	l1 := zap.NewAtomicLevel()
	logger, flush := New(
		"service-name",
		WithConsoleSink(&buf, WithLeveler(l1)),
	)

	childLogger := WithNamedLevel(logger, "child")

	SetLevelForControl(l1, 1)
	SetLevelFor("child", 0)

	logger.V(0).Info("line 1")
	logger.V(1).Info("line 2")
	logger.V(2).Info("line 3")
	childLogger.V(0).Info("line A")
	childLogger.V(1).Info("line B")
	childLogger.V(2).Info("line C")
	assert.Nil(t, flush())

	// output should contain up to verbosity 1 for parent
	// and verbosity 0 for child
	assert.Equal(t, []string{
		"info-0\tservice-name\tline 1",
		"info-1\tservice-name\tline 2",
		"info-0\tservice-name.child\tline A",
	}, splitLines(buf.String()))
}

func TestNestedWithNamedLevel(t *testing.T) {
	var buf bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	grandParent, flush := New("grandParent", WithConsoleSink(&buf, WithLevel(1)))
	parent := WithNamedLevel(grandParent, "parent")
	child := WithNamedLevel(parent, "child")

	SetLevelFor("parent", 0)
	SetLevelFor("child", 2)

	grandParent.V(0).Info("line 1")
	parent.V(0).Info("line 2")
	child.V(0).Info("line 3")

	grandParent.V(1).Info("line 4")
	parent.V(1).Info("line 5")
	child.V(1).Info("line 6")

	grandParent.V(2).Info("line 7")
	parent.V(2).Info("line 8")
	child.V(2).Info("line 9")

	assert.Nil(t, flush())

	lines := splitLines(buf.String())
	assert.Equal(t, 4, len(lines))

	assert.Equal(t, `info-0	grandParent	line 1`, lines[0])
	assert.Equal(t, `info-0	grandParent.parent	line 2`, lines[1])
	assert.Equal(t, `info-0	grandParent.parent.child	line 3`, lines[2])
	assert.Equal(t, `info-1	grandParent	line 4`, lines[3])
}

func TestSiblingsWithNamedLevel(t *testing.T) {
	var buf bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	parent, flush := New("parent", WithConsoleSink(&buf, WithLevel(1)))
	alice := WithNamedLevel(parent, "alice")
	bob := WithNamedLevel(parent, "bob")

	SetLevelFor("alice", 0)
	SetLevelFor("bob", 2)

	parent.V(0).Info("line 1")
	alice.V(0).Info("line 2")
	bob.V(0).Info("line 3")

	parent.V(1).Info("line 4")
	alice.V(1).Info("line 5")
	bob.V(1).Info("line 6")

	parent.V(2).Info("line 7")
	alice.V(2).Info("line 8")
	bob.V(2).Info("line 9")

	assert.Nil(t, flush())
	lines := splitLines(buf.String())
	assert.Equal(t, 5, len(lines))

	assert.Equal(t, `info-0	parent	line 1`, lines[0])
	assert.Equal(t, `info-0	parent.alice	line 2`, lines[1])
	assert.Equal(t, `info-0	parent.bob	line 3`, lines[2])
	assert.Equal(t, `info-1	parent	line 4`, lines[3])
	assert.Equal(t, `info-1	parent.bob	line 6`, lines[4])
}

func TestWithNamedLevelConcurrency(t *testing.T) {
	var buf bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	parent, flush := New("parent", WithConsoleSink(&buf))

	alice := WithNamedLevel(parent, "alice")
	bob := WithNamedLevel(parent, "bob")

	var wg sync.WaitGroup
	f := func(logger logr.Logger) {
		defer wg.Done()
		for i := 0; i < 100_000; i++ {
			logger.Info(fmt.Sprintf("%06d", i))
		}
	}
	wg.Add(3)
	go f(parent)
	go f(alice)
	go f(bob)
	wg.Wait()

	assert.Nil(t, flush())
	logLines := splitLines(buf.String())
	assert.Equal(t, 300_000, len(logLines))
	sort.Slice(logLines, func(i, j int) bool {
		return logLines[i] < logLines[j]
	})

	for i := 0; i < 100_000; i++ {
		assert.Equal(t, fmt.Sprintf("info-0\tparent\t%06d", i), logLines[i])
		assert.Equal(t, fmt.Sprintf("info-0\tparent.alice\t%06d", i), logLines[i+100_000])
		assert.Equal(t, fmt.Sprintf("info-0\tparent.bob\t%06d", i), logLines[i+200_000])
	}
}

func TestWithNamedLevelInheritance(t *testing.T) {
	t.Run("child inherits parent level", func(t *testing.T) {
		var buf bytes.Buffer
		globalControls = make(map[string]levelSetter, 16)

		parent, flush := New("parent", WithConsoleSink(&buf, WithLevel(2)))
		parent = parent.WithValues("key", "value")
		// child will inherit parent's log level 2
		child := WithNamedLevel(parent, "child")

		parent.V(2).Info("yay")
		child.V(2).Info("yay again")
		assert.Nil(t, flush())

		logLines := splitLines(buf.String())
		assert.Equal(t, []string{
			`info-2	parent	yay	{"key": "value"}`,
			`info-2	parent.child	yay again	{"key": "value"}`,
		}, logLines)
	})

	t.Run("child inherits existing named level", func(t *testing.T) {
		var buf bytes.Buffer
		globalControls = make(map[string]levelSetter, 16)

		parent, flush := New("parent", WithConsoleSink(&buf, WithLevel(2)))
		parent = parent.WithValues("key", "value")
		SetLevelFor("child", 0)
		// child will inherit existing named level 0
		child := WithNamedLevel(parent, "child")

		parent.V(2).Info("yay")
		child.V(2).Info("yay again")
		assert.Nil(t, flush())

		logLines := splitLines(buf.String())
		assert.Equal(t, []string{`info-2	parent	yay	{"key": "value"}`}, logLines)
	})
}

func TestExistingChildLevel(t *testing.T) {
	var buf bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	parent, flush := New("parent", WithConsoleSink(&buf, WithLevel(2)))

	SetLevelFor("child", 2)
	// child should start with a level of 2 due to SetLevelFor above
	child := WithNamedLevel(parent, "child")

	parent.V(2).Info("yay")
	child.V(2).Info("yay again")
	assert.Nil(t, flush())

	assert.Contains(t, buf.String(), "info-2\tparent\tyay")
	assert.Contains(t, buf.String(), "info-2\tparent.child\tyay again")
}

func TestSinkWithNamedLevel(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	parent, flush := New(
		"parent",
		WithConsoleSink(&buf1, WithLevel(0)),
		WithConsoleSink(&buf2, WithLevel(2)),
	)
	child := WithNamedLevel(parent, "child")

	for level := 0; level < 3; level++ {
		SetLevelFor("child", int8(level))
		child.Info("")
		child.V(1).Info("")
		child.V(2).Info("")
	}
	assert.Nil(t, flush())

	// buf1 should get only level 0 logs
	assert.Equal(t, []string{
		"info-0\tparent.child",
		"info-0\tparent.child",
		"info-0\tparent.child",
	}, splitLines(buf1.String()))

	assert.Equal(t, []string{
		// child level 0
		"info-0\tparent.child",
		// child level 1
		"info-0\tparent.child",
		"info-1\tparent.child",
		// child level 2
		"info-0\tparent.child",
		"info-1\tparent.child",
		"info-2\tparent.child",
	}, splitLines(buf2.String()))
}

func TestAddLeveler(t *testing.T) {
	l1, l2 := zap.NewAtomicLevel(), zap.NewAtomicLevel()
	logger, _ := New("parent", WithConsoleSink(io.Discard, WithLeveler(l1)))

	t.Run("child level more verbose", func(t *testing.T) {
		l1.SetLevel(0)
		l2.SetLevel(1)
		_, err := AddLeveler(logger, l2)
		assert.Nil(t, err)
	})

	t.Run("child level less verbose", func(t *testing.T) {
		l1.SetLevel(1)
		l2.SetLevel(0)
		_, err := AddLeveler(logger, l2)
		assert.Nil(t, err)
	})
}

func splitLines(s string) []string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	logLines := make([]string, len(lines))
	for i, logLine := range lines {
		// remove timestamp
		logLines[i] = strings.TrimSpace(logLine[strings.Index(logLine, "\t")+1:])
	}
	return logLines
}

func TestFindLevel(t *testing.T) {
	lvl := zap.NewAtomicLevel()
	logger, _ := New("parent", WithConsoleSink(io.Discard, WithLeveler(lvl)))

	for i := 0; i < 128; i++ {
		i8 := int8(i)
		SetLevelForControl(lvl, i8)
		assert.Equal(t, i8, findLevel(logger))
	}
}

func TestOverwriteWithNamedLevel(t *testing.T) {
	var buf bytes.Buffer
	globalControls = make(map[string]levelSetter, 16)

	parent, flush := New(
		"parent",
		WithConsoleSink(&buf, WithLevel(2)),
	)
	SetLevelFor("child", 0)
	child1 := WithNamedLevel(parent, "child")
	child2 := WithNamedLevel(parent, "child")
	SetLevelFor("child", 2)

	child1.V(2).Info("")
	child2.V(2).Info("")

	assert.Nil(t, flush())

	// buf1 should get only level 0 logs
	assert.Equal(t, []string{
		"info-2\tparent.child",
		"info-2\tparent.child",
	}, splitLines(buf.String()))
}
