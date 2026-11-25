package detectors

import (
	"math/rand"
	"testing"
)

func TestSortResults(t *testing.T) {
	results := []Result{
		{Redacted: "b", RawV2: []byte("b2")},
		{Redacted: "a", RawV2: []byte("a2"), Raw: []byte("second")},
		{Redacted: "a", RawV2: []byte("a1")},
		{Redacted: "a", RawV2: []byte("a2"), Raw: []byte("first")},
		{Redacted: ""},
	}

	SortResults(results)

	want := []Result{
		{Redacted: ""},
		{Redacted: "a", RawV2: []byte("a1")},
		{Redacted: "a", RawV2: []byte("a2"), Raw: []byte("first")},
		{Redacted: "a", RawV2: []byte("a2"), Raw: []byte("second")},
		{Redacted: "b", RawV2: []byte("b2")},
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for i := range want {
		if results[i].Redacted != want[i].Redacted || string(results[i].RawV2) != string(want[i].RawV2) || string(results[i].Raw) != string(want[i].Raw) {
			t.Errorf("results[%d] = %q/%q/%q, want %q/%q/%q", i, results[i].Redacted, results[i].RawV2, results[i].Raw, want[i].Redacted, want[i].RawV2, want[i].Raw)
		}
	}
}

func TestCleanResults_VerifiedOutputIsSorted(t *testing.T) {
	results := []Result{
		{Redacted: "c", Verified: true},
		{Redacted: "a", Verified: true},
		{Redacted: "x"},
		{Redacted: "b", Verified: true},
	}
	want := []string{"a", "b", "c"}

	for i := 0; i < 50; i++ {
		in := make([]Result, len(results))
		copy(in, results)
		out := CleanResults(in, true)

		if len(out) != len(want) {
			t.Fatalf("iteration %d: got %d results, want %d", i, len(out), len(want))
		}
		for j := range want {
			if out[j].Redacted != want[j] {
				t.Fatalf("iteration %d: results[%d].Redacted = %q, want %q", i, j, out[j].Redacted, want[j])
			}
		}
	}
}

func TestCleanResults_UnverifiedSurvivorIsSorted(t *testing.T) {
	candidates := []Result{
		{Redacted: "c"},
		{Redacted: "a", RawV2: []byte("a2")},
		{Redacted: "a", RawV2: []byte("a1")},
		{Redacted: "b"},
	}

	for i := 0; i < 50; i++ {
		in := make([]Result, len(candidates))
		copy(in, candidates)
		rand.Shuffle(len(in), func(x, y int) { in[x], in[y] = in[y], in[x] })

		out := CleanResults(in, true)

		if len(out) != 1 {
			t.Fatalf("iteration %d: got %d results, want 1", i, len(out))
		}
		if out[0].Redacted != "a" || string(out[0].RawV2) != "a1" {
			t.Fatalf("iteration %d: kept %q/%q, want a/a1", i, out[0].Redacted, out[0].RawV2)
		}
	}
}
