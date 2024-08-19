package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultCleanResults(t *testing.T) {
	testCases := []struct {
		name                string
		resultsToClean      []Result
		wantVerifiedCount   int
		wantUnverifiedCount int
	}{
		{
			name: "all unverified",
			resultsToClean: []Result{
				{Redacted: "abc", Verified: false},
				{Redacted: "def", Verified: false},
			},
			wantVerifiedCount:   0,
			wantUnverifiedCount: 1,
		},
		{
			name: "all verified",
			resultsToClean: []Result{
				{Redacted: "abc", Verified: true},
				{Redacted: "def", Verified: true},
			},
			wantVerifiedCount:   2,
			wantUnverifiedCount: 0,
		},
		{
			name: "mixed verified/unverified",
			resultsToClean: []Result{
				{Redacted: "abc", Verified: true},
				{Redacted: "def", Verified: false},
				{Redacted: "ghi", Verified: true},
			},
			wantVerifiedCount:   2,
			wantUnverifiedCount: 0,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			cleaner := DefaultResultsCleaner{}

			cleaned := cleaner.CleanResults(tt.resultsToClean)

			gotVerifiedCount := 0
			gotUnverifiedCount := 0
			for _, r := range cleaned {
				if r.Verified {
					gotVerifiedCount++
				} else {
					gotUnverifiedCount++
				}
			}

			assert.Equal(t, tt.wantVerifiedCount, gotVerifiedCount)
			assert.Equal(t, tt.wantUnverifiedCount, gotUnverifiedCount)
		})
	}
}
