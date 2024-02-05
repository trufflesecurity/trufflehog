package sourcestest

import (
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type reporter interface {
	sources.UnitReporter
	sources.ChunkReporter
}

var (
	_ reporter = (*TestReporter)(nil)
	_ reporter = (*ErrReporter)(nil)
)

// TestReporter is a helper struct that implements both UnitReporter and
// ChunkReporter by simply recording the values passed in the methods.
type TestReporter struct {
	Units     []sources.SourceUnit
	UnitErrs  []error
	Chunks    []sources.Chunk
	ChunkErrs []error
}

func (t *TestReporter) UnitOk(_ context.Context, unit sources.SourceUnit) error {
	t.Units = append(t.Units, unit)
	return nil
}
func (t *TestReporter) UnitErr(_ context.Context, err error) error {
	t.UnitErrs = append(t.UnitErrs, err)
	return nil
}
func (t *TestReporter) ChunkOk(_ context.Context, chunk sources.Chunk) error {
	t.Chunks = append(t.Chunks, chunk)
	return nil
}
func (t *TestReporter) ChunkErr(_ context.Context, err error) error {
	t.ChunkErrs = append(t.ChunkErrs, err)
	return nil
}

// ErrReporter implements UnitReporter and ChunkReporter but always returns an
// error.
type ErrReporter struct{}

func (ErrReporter) UnitOk(context.Context, sources.SourceUnit) error {
	return fmt.Errorf("ErrReporter: UnitOk error")
}
func (ErrReporter) UnitErr(context.Context, error) error {
	return fmt.Errorf("ErrReporter: UnitErr error")
}
func (ErrReporter) ChunkOk(context.Context, sources.Chunk) error {
	return fmt.Errorf("ErrReporter: ChunkOk error")
}
func (ErrReporter) ChunkErr(context.Context, error) error {
	return fmt.Errorf("ErrReporter: ChunkErr error")
}
