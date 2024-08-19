package detectors

type ResultsCleaner interface {
	CleanResults(results []Result) []Result
	ShouldCleanIrrespectiveOfConfiguration() bool
}

type DefaultResultsCleaner struct {
}

var _ ResultsCleaner = (*DefaultResultsCleaner)(nil)

func (d DefaultResultsCleaner) CleanResults(results []Result) []Result {
	panic("not implemented")
}

func (d DefaultResultsCleaner) ShouldCleanIrrespectiveOfConfiguration() bool {
	return false
}
