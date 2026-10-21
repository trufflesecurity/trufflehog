package s3

import (
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// unitProgress tracks how far a unit scan has got through its bucket and publishes it on the source's
// Progress under the unit's ID. Each ChunkUnit call has its own, so buckets scanned at the same time
// never mix their counts.
type unitProgress struct {
	unitID   string
	progress *sources.Progress

	mu       sync.Mutex
	current  sources.UnitProgress
	finished bool
}

func newUnitProgress(unitID string, progress *sources.Progress) *unitProgress {
	return &unitProgress{unitID: unitID, progress: progress}
}

// update applies f and publishes the result. Publishing under the lock keeps an older value from
// replacing a newer one. Nothing changes once the unit has finished.
func (p *unitProgress) update(f func(current *sources.UnitProgress)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	f(&p.current)
	p.progress.SetUnitProgressFor(p.unitID, p.current)
}

// objectDone records that the scan is finished with an object it downloads, whether or not the
// download worked. It does nothing on a nil receiver, which is how a legacy scan runs.
func (p *unitProgress) objectDone(size int64) {
	if p == nil {
		return
	}
	p.update(func(current *sources.UnitProgress) {
		current.ItemsDone++
		current.BytesDone += uint64(max(size, 0))
	})
}

// counted adds a listed page to the totals. Objects an earlier run finished count as done too.
func (p *unitProgress) counted(items, bytes, resumedItems, resumedBytes uint64) {
	p.update(func(current *sources.UnitProgress) {
		current.ItemsTotal += items
		current.BytesTotal += bytes
		current.ItemsDone += resumedItems
		current.BytesDone += resumedBytes
		current.ResumedBytes += resumedBytes
	})
}

func (p *unitProgress) setState(state sources.UnitProgressState) {
	p.update(func(current *sources.UnitProgress) { current.State = state })
}

// finish settles the totals once the scan of the bucket has ended. scannedWholeBucket means the scan
// listed the bucket from the start to the end, so it has seen every object there is.
func (p *unitProgress) finish(scannedWholeBucket bool) {
	p.update(func(current *sources.UnitProgress) {
		switch {
		case current.State == sources.UnitProgressReady:
			// Objects added during the scan can take the done count past the total.
			current.ItemsTotal = max(current.ItemsTotal, current.ItemsDone)
			current.BytesTotal = max(current.BytesTotal, current.BytesDone)
		case scannedWholeBucket:
			// The count pass did not get to the end, but the scan did, so what it did is the total.
			current.ItemsTotal = current.ItemsDone
			current.BytesTotal = current.BytesDone
			current.State = sources.UnitProgressReady
		default:
			current.State = sources.UnitProgressUnavailable
		}
		p.finished = true
	})
}

// startCount runs the count pass alongside the scan. It returns a function that stops the count and
// waits for it to exit, so nothing is counted after the unit finishes.
func (s *Source) startCount(
	ctx context.Context,
	client *s3.Client,
	bucket string,
	startAfter *string,
	progress *unitProgress,
) func() {
	countCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	progress.setState(sources.UnitProgressCounting)
	go func() {
		defer close(done)
		defer common.Recover(countCtx)
		s.countBucket(countCtx, client, bucket, startAfter, progress)
	}()

	return func() {
		cancel()
		<-done
	}
}

// countBucket lists the bucket from the start, the same way the scan does, to add up the objects the
// scan downloads and their size, since S3 has no API that reports either. Keys at or before startAfter
// were finished by an earlier run, so they count as done too. Nothing is kept per object.
func (s *Source) countBucket(
	ctx context.Context,
	client *s3.Client,
	bucket string,
	startAfter *string,
	progress *unitProgress,
) {
	paginator := newBucketPaginator(client, s.listInputs(bucket, nil))
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// A cancelled count means the unit has finished, and finish settles the totals.
			if ctx.Err() == nil {
				ctx.Logger().V(2).Info("could not count objects for progress", "bucket", bucket, "err", err)
				progress.setState(sources.UnitProgressUnavailable)
			}
			return
		}

		var items, bytes, resumedItems, resumedBytes uint64
		for _, obj := range page.Contents {
			if s.skipReason(obj) != "" {
				continue
			}
			size := uint64(max(*obj.Size, 0))
			items++
			bytes += size
			if startAfter != nil && *obj.Key <= *startAfter {
				resumedItems++
				resumedBytes += size
			}
		}
		progress.counted(items, bytes, resumedItems, resumedBytes)
	}
	progress.setState(sources.UnitProgressReady)
}
