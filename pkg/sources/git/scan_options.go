package git

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type ScanOptions struct {
	Filter     *common.Filter
	BaseCommit *object.Commit // When scanning a git.Log, this is the oldest/first commit.
	HeadCommit *object.Commit
	MaxDepth   int64
	LogOptions *git.LogOptions
}

type ScanOption func(*ScanOptions)

func ScanOptionFilter(filter *common.Filter) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.Filter = filter
	}
}

func ScanOptionBaseCommit(commit *object.Commit) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.BaseCommit = commit
	}
}

func ScanOptionHeadCommit(commit *object.Commit) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.HeadCommit = commit
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
		Filter:     common.FilterEmpty(),
		BaseCommit: nil,
		MaxDepth:   -1,
		LogOptions: &git.LogOptions{
			All: true,
		},
	}
	for _, option := range options {
		option(scanOptions)
	}
	return scanOptions
}
