package github

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

type ScanOptions struct {
	GitScanOptions *git.ScanOptions
	Visibility     []source_metadatapb.Visibility
}

type ScanOption func(*ScanOptions)

func ScanOptionGitScanOptions(opts git.ScanOptions) ScanOption {
	return func(scanOptions *ScanOptions) {
		scanOptions.GitScanOptions = &opts
	}
}

func getValidVisibilityScanOption(optVis string) source_metadatapb.Visibility {

	optVis = strings.TrimSpace(optVis)

	switch optVis {
	case "public", "private", "shared":
		return source_metadatapb.Visibility(source_metadatapb.Visibility_value[optVis])

	default:
		return -1 // TODO: better error handling
	}
}

func ScanOptionVisibility(optVis string) ScanOption {

	optVis = strings.ToLower(optVis)
	visEnum := []source_metadatapb.Visibility{}

	if strings.Contains(optVis, ",") {
		strArr := strings.Split(optVis, ",")
		for i := 0; i < len(strArr); i++ {
			tempVis := getValidVisibilityScanOption(strArr[i])
			if tempVis != -1 { // invalid option specified, TODO: better error handling
				visEnum = append(visEnum, tempVis)
			}
		}
	} else {
		tempVis := getValidVisibilityScanOption(optVis)
		if tempVis != -1 { // invalid option specified, TODO: better error handling
			visEnum = []source_metadatapb.Visibility{getValidVisibilityScanOption(optVis)}
		}
	}

	return func(scanOptions *ScanOptions) {
		scanOptions.Visibility = visEnum
	}
}

func NewScanOptions(options ...ScanOption) *ScanOptions {
	scanOptions := &ScanOptions{
		GitScanOptions: nil,
		Visibility:     []source_metadatapb.Visibility{},
	}
	for _, option := range options {
		option(scanOptions)
	}
	return scanOptions
}
