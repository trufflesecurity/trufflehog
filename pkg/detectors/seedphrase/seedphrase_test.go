package seedphrase

import (
	"slices"
	"testing"
)

func TestNormalizeWords(t *testing.T) {
	input := []byte("1. Alpha,\t2. BETA\nthree-four five's SIX")
	want := []string{"alpha", "beta", "three", "four", "five", "s", "six"}

	got := NormalizeWords(input)
	if !slices.Equal(got, want) {
		t.Fatalf("NormalizeWords() = %#v, want %#v", got, want)
	}
}

func TestHasOnlyOneUniqueWord(t *testing.T) {
	tests := []struct {
		name  string
		words []string
		want  bool
	}{
		{
			name: "empty",
			want: false,
		},
		{
			name:  "one word",
			words: []string{"abandon"},
			want:  true,
		},
		{
			name:  "same word repeated",
			words: []string{"abandon", "abandon", "abandon"},
			want:  true,
		},
		{
			name:  "multiple words",
			words: []string{"abandon", "ability", "abandon"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasOnlyOneUniqueWord(tt.words)
			if got != tt.want {
				t.Fatalf("HasOnlyOneUniqueWord(%#v) = %t, want %t", tt.words, got, tt.want)
			}
		})
	}
}

func TestFindCandidatesFixedLength(t *testing.T) {
	words := []string{"skip", "alpha", "beta", "gamma", "skip"}
	valid := func(words []string) bool {
		return slices.Equal(words, []string{"alpha", "beta", "gamma"})
	}

	got := FindCandidates(words, []int{3}, valid)
	want := []Candidate{
		{
			Start:  1,
			End:    4,
			Phrase: "alpha beta gamma",
		},
	}

	if !slices.Equal(got, want) {
		t.Fatalf("FindCandidates() = %#v, want %#v", got, want)
	}
}

func TestFindCandidatesMultipleLengths(t *testing.T) {
	words := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	valid := func(words []string) bool {
		return len(words) == 3 || len(words) == 4
	}

	got := FindCandidates(words, []int{4, 3}, valid)
	want := []Candidate{
		{
			Start:  0,
			End:    4,
			Phrase: "alpha beta gamma delta",
		},
		{
			Start:  1,
			End:    5,
			Phrase: "beta gamma delta epsilon",
		},
		{
			Start:  2,
			End:    5,
			Phrase: "gamma delta epsilon",
		},
	}

	if !slices.Equal(got, want) {
		t.Fatalf("FindCandidates() = %#v, want %#v", got, want)
	}
}

func TestFindCandidatesDeduplicatesPhrases(t *testing.T) {
	words := []string{"alpha", "beta", "alpha", "beta"}
	valid := func(words []string) bool {
		return true
	}

	got := FindCandidates(words, []int{2}, valid)
	want := []Candidate{
		{
			Start:  0,
			End:    2,
			Phrase: "alpha beta",
		},
		{
			Start:  1,
			End:    3,
			Phrase: "beta alpha",
		},
	}

	if !slices.Equal(got, want) {
		t.Fatalf("FindCandidates() = %#v, want %#v", got, want)
	}
}

func TestFindCandidatesTriesShorterLengthAfterDuplicate(t *testing.T) {
	words := []string{"alpha", "beta", "gamma", "alpha", "beta", "gamma", "delta"}
	valid := func(words []string) bool {
		return slices.Equal(words, []string{"alpha", "beta", "gamma"}) ||
			slices.Equal(words, []string{"alpha", "beta"}) ||
			slices.Equal(words, []string{"beta", "gamma", "delta"})
	}

	got := FindCandidates(words, []int{3, 2}, valid)
	want := []Candidate{
		{
			Start:  0,
			End:    3,
			Phrase: "alpha beta gamma",
		},
		{
			Start:  3,
			End:    5,
			Phrase: "alpha beta",
		},
		{
			Start:  4,
			End:    7,
			Phrase: "beta gamma delta",
		},
	}

	if !slices.Equal(got, want) {
		t.Fatalf("FindCandidates() = %#v, want %#v", got, want)
	}
}

func TestFindCandidatesSkipsRepeatedWordWindows(t *testing.T) {
	words := []string{"alpha", "alpha", "alpha", "beta"}
	valid := func(words []string) bool {
		return true
	}

	got := FindCandidates(words, []int{3}, valid)
	want := []Candidate{
		{
			Start:  1,
			End:    4,
			Phrase: "alpha alpha beta",
		},
	}

	if !slices.Equal(got, want) {
		t.Fatalf("FindCandidates() = %#v, want %#v", got, want)
	}
}

func TestRemoveContainedCandidates(t *testing.T) {
	candidates := []Candidate{
		{
			Start:  0,
			End:    24,
			Phrase: "long",
		},
		{
			Start:  0,
			End:    12,
			Phrase: "prefix",
		},
		{
			Start:  5,
			End:    17,
			Phrase: "middle",
		},
		{
			Start:  24,
			End:    36,
			Phrase: "separate",
		},
	}

	got := RemoveContainedCandidates(candidates)
	want := []Candidate{
		{
			Start:  0,
			End:    24,
			Phrase: "long",
		},
		{
			Start:  24,
			End:    36,
			Phrase: "separate",
		},
	}

	if !slices.Equal(got, want) {
		t.Fatalf("RemoveContainedCandidates() = %#v, want %#v", got, want)
	}
}
