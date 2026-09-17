package git

import (
	"github.com/go-git/go-git/v5"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type ScanOptions struct {
	Filter       *common.Filter
	BaseHash     string // When scanning a git.Log, this is the oldest/first commit.
	HeadHash     string
	MaxDepth     int64
	Bare         bool
	ExcludeGlobs []string
	LogOptions   *git.LogOptions
}

type ScanOption func(*ScanOptions)

func ScanOptionFilter(filter *common.Filter) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.Filter = filter
	}
}

func ScanOptionBaseHash(hash string) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.BaseHash = hash
	}
}

func ScanOptionHeadCommit(hash string) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.HeadHash = hash
	}
}

func ScanOptionMaxDepth(maxDepth int64) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.MaxDepth = maxDepth
	}
}

func ScanOptionExcludeGlobs(globs []string) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.ExcludeGlobs = globs
	}
}

func ScanOptionLogOptions(logOptions *git.LogOptions) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.LogOptions = logOptions
	}
}

func ScanOptionBare(bare bool) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.Bare = bare
	}
}

func NewScanOptions(options ...ScanOption) *ScanOptions {
	scanOptions := &ScanOptions{
		Filter:   common.FilterEmpty(),
		BaseHash: "",
		HeadHash: "",
		MaxDepth: -1,
		LogOptions: &git.LogOptions{
			All: true,
		},
	}
	for _, option := range options {
		option(scanOptions)
	}
	return scanOptions
}
