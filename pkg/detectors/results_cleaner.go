package detectors

// ResultsCleaner defines an interface for "cleaning" results (eliminating superfluous results) and controlling aspects
// of when this cleaning runs.
type ResultsCleaner interface {
	// CleanResults removes results from a set that are considered unnecessary. The default implementation removes all
	// unverified results if any verified results are present, and all but one result if no verified results are
	// present.
	CleanResults(results []Result) []Result

	// ShouldCleanIrrespectiveOfConfiguration controls whether results cleaning should happen irrespective of
	// TruffleHog's runtime configuration. This option exists because some detectors are opinionated about whether their
	// cleaning logic should run.
	ShouldCleanIrrespectiveOfConfiguration() bool
}

// DefaultResultsCleaner can be embedded into detectors that do not need to customize their cleaning logic.
type DefaultResultsCleaner struct{}

var _ ResultsCleaner = (*DefaultResultsCleaner)(nil)

func (d DefaultResultsCleaner) CleanResults(results []Result) []Result {
	if len(results) == 0 {
		return results
	}

	var cleaned = make(map[string]Result, 0)

	for _, s := range results {
		if s.Verified {
			cleaned[s.Redacted] = s
		}
	}

	if len(cleaned) == 0 {
		return results[:1]
	}

	results = results[:0]
	for _, r := range cleaned {
		results = append(results, r)
	}

	return results
}

func (d DefaultResultsCleaner) ShouldCleanIrrespectiveOfConfiguration() bool {
	return false
}
