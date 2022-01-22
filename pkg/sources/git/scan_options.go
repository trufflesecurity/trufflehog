package git

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/trufflesecurity/trufflehog/pkg/common"
)

type ScanOptions struct {
	Filter      *common.Filter
	SinceCommit *object.Commit // When scanning a git.Log, this is the oldest/first commit.
	MaxDepth    int64
	LogOptions  *git.LogOptions
}

type ScanOption func(*ScanOptions)

func ScanOptionFilter(filter *common.Filter) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.Filter = filter
	}
}

func ScanOptionSinceCommit(commit *object.Commit) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.SinceCommit = commit
	}
}

func ScanOptionMaxDepth(maxDepth int64) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.MaxDepth = maxDepth
	}
}

func ScanOptionLogOptions(logOptions *git.LogOptions) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.LogOptions = logOptions
	}
}

func NewScanOptions(options ...ScanOption) *ScanOptions {
	scanOptions := &ScanOptions{
		Filter:      common.FilterEmpty(),
		SinceCommit: nil,
		MaxDepth:    -1,
		LogOptions: &git.LogOptions{
			All:   true,
			Order: git.LogOrderCommitterTime,
		},
	}
	for _, option := range options {
		option(scanOptions)
	}
	return scanOptions
}
