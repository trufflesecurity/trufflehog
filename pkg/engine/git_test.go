package engine

import (
	"context"
	"os"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func TestGitEngine(t *testing.T) {
	repoUrl := "https://github.com/dustin-decker/secretsandstuff.git"
	path, _, err := git.PrepareRepo(repoUrl)
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(path)

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()
	type testProfile struct {
		expected map[string]string
		branch   string
		base     string
		maxDepth int
		filter   *common.Filter
	}
	for tName, tTest := range map[string]testProfile{
		"all_secrets": {
			expected: map[string]string{
				"70001020fab32b1fcf2f1f0e5c66424eae649826": "AKIAXYZDQCEN4B6JSJQI",
				"90c75f884c65dc3638ca1610bd9844e668f213c2": "AKIAILE3JG6KMS3HZGCA",
				"8afb0ecd4998b1179e428db5ebbcdc8221214432": "369963c1434c377428ca8531fbc46c0c43d037a0",
				"27fbead3bf883cdb7de9d7825ed401f28f9398f1": "ffc7e0f9400fb6300167009e42d2f842cd7956e2",
			},
			filter: common.FilterEmpty(),
		},
		"base_commit": {
			expected: map[string]string{
				"70001020fab32b1fcf2f1f0e5c66424eae649826": "AKIAXYZDQCEN4B6JSJQI",
			},
			filter: common.FilterEmpty(),
			base:   "2f251b8c1e72135a375b659951097ec7749d4af9",
		},
	} {
		e := Start(ctx,
			WithConcurrency(1),
			WithDecoders(decoders.DefaultDecoders()...),
			WithDetectors(false, DefaultDetectors()...),
		)
		e.ScanGit(ctx, path, tTest.branch, tTest.base, tTest.maxDepth, tTest.filter)
		resultCount := 0
		for result := range e.ResultsChan() {
			switch meta := result.SourceMetadata.GetData().(type) {
			case *source_metadatapb.MetaData_Git:
				if tTest.expected[meta.Git.Commit] != string(result.Raw) {
					t.Errorf("%s: unexpected result. Got: %s, Expected: %s", tName, string(result.Raw), tTest.expected[meta.Git.Commit])
				}
			}
			resultCount++

		}
		if resultCount != len(tTest.expected) {
			t.Errorf("%s: unexpected number of results. Got: %d, Expected: %d", tName, resultCount, len(tTest.expected))
		}
	}
}
