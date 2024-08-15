package detectors

type ResultsCleaner interface {
	CleanResults(results []Result) []Result
}

type DefaultResultsCleaner struct {
}

var _ ResultsCleaner = (*DefaultResultsCleaner)(nil)

func (d DefaultResultsCleaner) CleanResults(results []Result) []Result {
	panic("not implemented")
}
