package github

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// This isn't really a GitHub test, but GitHub is the only source that supports scan targeting right now, so this is
// where I've put this targeted scan test.
func Test_ScanMultipleTargets_MultipleErrors(t *testing.T) {
	s := &Source{conn: &sourcespb.GitHub{}} // This test doesn't require initialization
	ctx := context.Background()
	chunksChan := make(chan *sources.Chunk)

	targets := []sources.ChunkingTarget{
		{SecretID: 1},
		{SecretID: 2},
	}

	// The specific error text doesn't matter for the test, but it has to match what the source generates
	want := []*sources.TargetedScanError{
		{SecretID: 1, Err: errors.New("unable to cast metadata type for targeted scan")},
		{SecretID: 2, Err: errors.New("unable to cast metadata type for targeted scan")},
	}

	err := s.Chunks(ctx, chunksChan, targets...)
	unwrappable, ok := err.(interface{ Unwrap() []error })
	if assert.True(t, ok, "returned error was not unwrappable") {
		got := unwrappable.Unwrap()
		assert.ElementsMatch(t, got, want)
	}
}
