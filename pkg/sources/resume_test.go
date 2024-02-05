package sources

import (
	"reflect"
	"testing"
)

func TestRemoveRepoFromResumeInfo(t *testing.T) {
	tests := []struct {
		startingResumeInfoSlice []string
		repoURL                 string
		wantResumeInfoSlice     []string
	}{
		{
			startingResumeInfoSlice: []string{"a", "b", "c"},
			repoURL:                 "a",
			wantResumeInfoSlice:     []string{"b", "c"},
		},
		{
			startingResumeInfoSlice: []string{"a", "b", "c"},
			repoURL:                 "b",
			wantResumeInfoSlice:     []string{"a", "c"},
		},
		{ // This is the probably can't happen case of a repo not in the list.
			startingResumeInfoSlice: []string{"a", "b", "c"},
			repoURL:                 "not in the list",
			wantResumeInfoSlice:     []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		gotResumeInfoSlice := RemoveRepoFromResumeInfo(tt.startingResumeInfoSlice, tt.repoURL)
		if !reflect.DeepEqual(gotResumeInfoSlice, tt.wantResumeInfoSlice) {
			t.Errorf("RemoveRepoFromResumeInfo() got: %v, want: %v", gotResumeInfoSlice, tt.wantResumeInfoSlice)
		}
	}
}

func TestEncodeResumeInfo(t *testing.T) {
	tests := []struct {
		startingResumeInfoSlice []string
		wantEncodedResumeInfo   string
	}{
		{
			startingResumeInfoSlice: []string{"a", "b", "c"},
			wantEncodedResumeInfo:   "a\tb\tc",
		},
		{
			startingResumeInfoSlice: []string{},
			wantEncodedResumeInfo:   "",
		},
	}

	for _, tt := range tests {
		gotEncodedResumeInfo := EncodeResumeInfo(tt.startingResumeInfoSlice)
		if gotEncodedResumeInfo != tt.wantEncodedResumeInfo {
			t.Errorf("EncodeResumeInfo() got: %q, want: %q", gotEncodedResumeInfo, tt.wantEncodedResumeInfo)
		}
	}
}

func Test_decodeResumeInfo(t *testing.T) {
	tests := []struct {
		resumeInfo          string
		wantResumeInfoSlice []string
	}{
		{
			resumeInfo:          "a\tb\tc",
			wantResumeInfoSlice: []string{"a", "b", "c"},
		},
		{
			resumeInfo:          "",
			wantResumeInfoSlice: nil,
		},
	}

	for _, tt := range tests {
		gotResumeInfoSlice := DecodeResumeInfo(tt.resumeInfo)
		if !reflect.DeepEqual(gotResumeInfoSlice, tt.wantResumeInfoSlice) {
			t.Errorf("DecodeResumeInfo() got: %v, want: %v", gotResumeInfoSlice, tt.wantResumeInfoSlice)
		}
	}
}

func Test_filterReposToResume(t *testing.T) {
	startingRepos := []string{"a", "b", "c", "d", "e", "f", "g"}

	tests := map[string]struct {
		resumeInfo              string
		wantProgressOffsetCount int
		wantReposToScan         []string
	}{
		"blank resume info": {
			resumeInfo:              "",
			wantProgressOffsetCount: 0,
			wantReposToScan:         startingRepos,
		},
		"starting repos": {
			resumeInfo:              "a\tb",
			wantProgressOffsetCount: 0,
			wantReposToScan:         startingRepos,
		},
		"early contiguous repos": {
			resumeInfo:              "b\tc",
			wantProgressOffsetCount: 1,
			wantReposToScan:         []string{"b", "c", "d", "e", "f", "g"},
		},
		"non-contiguous repos": {
			resumeInfo:              "b\te",
			wantProgressOffsetCount: 3,
			wantReposToScan:         []string{"b", "e", "f", "g"},
		},
		"no repos found in the repo list": {
			resumeInfo:              "not\tthere",
			wantProgressOffsetCount: 0,
			wantReposToScan:         startingRepos,
		},
		"only some repos in the list": {
			resumeInfo:              "c\tnot\tthere",
			wantProgressOffsetCount: 2,
			wantReposToScan:         []string{"c", "d", "e", "f", "g"},
		},
	}

	for name, tt := range tests {
		gotReposToScan, gotProgressOffsetCount := FilterReposToResume(startingRepos, tt.resumeInfo)
		if !reflect.DeepEqual(gotReposToScan, tt.wantReposToScan) {
			t.Errorf("FilterReposToResume() name: %q got: %v, want: %v", name, gotReposToScan, tt.wantReposToScan)
		}
		if gotProgressOffsetCount != tt.wantProgressOffsetCount {
			t.Errorf("FilterReposToResume() name: %q got: %d, want: %d", name, gotProgressOffsetCount, tt.wantProgressOffsetCount)
		}
	}
}
