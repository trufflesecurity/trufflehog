package engine

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type expResult struct {
	B          string
	LineNumber int64
	Verified   bool
}

type discardPrinter struct{}

func (p *discardPrinter) Print(context.Context, *detectors.ResultWithMetadata) error {
	// This method intentionally does nothing.
	return nil
}

func TestGitEngine(t *testing.T) {
	ctx := context.Background()
	repoUrl := "https://github.com/dustin-decker/secretsandstuff.git"
	path, _, err := git.PrepareRepo(ctx, repoUrl)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(path)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type testProfile struct {
		expected map[string]expResult
		branch   string
		base     string
		maxDepth int
	}
	for tName, tTest := range map[string]testProfile{
		"all_secrets": {
			expected: map[string]expResult{
				"70001020fab32b1fcf2f1f0e5c66424eae649826": {"AKIAXYZDQCEN4B6JSJQI", 2, true},
				"84e9c75e388ae3e866e121087ea2dd45a71068f2": {"AKIAILE3JG6KMS3HZGCA", 4, true},
				"8afb0ecd4998b1179e428db5ebbcdc8221214432": {"369963c1434c377428ca8531fbc46c0c43d037a0", 3, false},
				"27fbead3bf883cdb7de9d7825ed401f28f9398f1": {"ffc7e0f9400fb6300167009e42d2f842cd7956e2", 7, false},
			},
		},
		"base_commit": {
			expected: map[string]expResult{
				"70001020fab32b1fcf2f1f0e5c66424eae649826": {"AKIAXYZDQCEN4B6JSJQI", 2, true},
			},
			base: "2f251b8c1e72135a375b659951097ec7749d4af9",
		},
	} {
		t.Run(tName, func(t *testing.T) {
			e, err := Start(ctx,
				WithConcurrency(1),
				WithDecoders(decoders.DefaultDecoders()...),
				WithDetectors(DefaultDetectors()...),
				WithVerify(true),
				WithPrinter(new(discardPrinter)),
			)
			assert.Nil(t, err)

			cfg := sources.GitConfig{
				URI:      path,
				HeadRef:  tTest.branch,
				BaseRef:  tTest.base,
				MaxDepth: tTest.maxDepth,
			}
			if err := e.ScanGit(ctx, cfg); err != nil {
				return
			}

			// Wait for all the chunks to be processed.
			assert.Nil(t, e.Finish(ctx))
			for result := range e.ResultsChan() {
				switch meta := result.SourceMetadata.GetData().(type) {
				case *source_metadatapb.MetaData_Git:
					if tTest.expected[meta.Git.Commit].B != string(result.Raw) {
						t.Errorf("%s: unexpected result. Got: %s, Expected: %s", tName, string(result.Raw), tTest.expected[meta.Git.Commit].B)
					}
					if tTest.expected[meta.Git.Commit].LineNumber != result.SourceMetadata.GetGit().Line {
						t.Errorf("%s: unexpected line number. Got: %d, Expected: %d", tName, result.SourceMetadata.GetGit().Line, tTest.expected[meta.Git.Commit].LineNumber)
					}
					if tTest.expected[meta.Git.Commit].Verified != result.Verified {
						t.Errorf("%s: unexpected verification. Got: %v, Expected: %v", tName, result.Verified, tTest.expected[meta.Git.Commit].Verified)
					}
				}

			}
			metrics := e.GetMetrics()
			assert.Equal(t, len(tTest.expected), int(metrics.VerifiedSecretsFound)+int(metrics.UnverifiedSecretsFound))
		})
	}
}

func BenchmarkGitEngine(b *testing.B) {
	ctx := context.Background()
	repoUrl := "https://github.com/dustin-decker/secretsandstuff.git"

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	e, err := Start(ctx,
		WithConcurrency(runtime.NumCPU()),
		WithDecoders(decoders.DefaultDecoders()...),
		WithDetectors(DefaultDetectors()...),
		WithVerify(false),
		WithPrinter(new(discardPrinter)),
	)
	assert.Nil(b, err)

	go func() {
		resultCount := 0
		for range e.ResultsChan() {
			resultCount++
		}
	}()

	cfg := sources.GitConfig{URI: repoUrl}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := e.ScanGit(ctx, cfg); err != nil {
			return
		}
	}
	assert.Nil(b, e.Finish(ctx))
}
