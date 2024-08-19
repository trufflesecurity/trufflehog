package detectors

// ResultsCleaner defines an interface for "cleaning" results (eliminating superfluous unverified results) and
// controlling aspects of when this cleaning runs.
type ResultsCleaner interface {
	// CleanResults removes results from a set that are considered unnecessary. Typically, this will entail the removal
	// of unverified results if any verified results are present, and the removal of all but one results if no verified
	// results are present.
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
	panic("not implemented")
}

func (d DefaultResultsCleaner) ShouldCleanIrrespectiveOfConfiguration() bool {
	return false
}
