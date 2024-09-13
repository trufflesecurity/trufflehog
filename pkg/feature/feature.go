package feature

import "sync/atomic"

var (
	ForceSkipBinaries  = atomic.Bool{}
	ForceSkipArchives  = atomic.Bool{}
	SkipAdditionalRefs = atomic.Bool{}
)
