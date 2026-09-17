package s3

import (
	"math"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const progressMessage = "Scanning objects"

// scanProgress aggregates object and byte counts across every bucket the source is scanning,
// so that concurrent ChunkUnit calls sharing one Progress publish one consistent number.
type scanProgress struct {
	objectsDone, bytesDone   atomic.Uint64
	objectsTotal, bytesTotal atomic.Uint64

	// listingsInFlight is the number of buckets whose count pass has not finished.
	// Percent is unknown while it is non-zero.
	listingsInFlight atomic.Int32

	// countFailed is set when a count pass could not list its whole bucket,
	// leaving the totals too low to divide by.
	countFailed atomic.Bool
}

func (p *scanProgress) addDone(objects, bytes uint64) {
	p.objectsDone.Add(objects)
	p.bytesDone.Add(bytes)
}

func (p *scanProgress) addTotal(objects, bytes uint64) {
	p.objectsTotal.Add(objects)
	p.bytesTotal.Add(bytes)
}

// percent returns the share of bytes done, capped at 99 because only the unit finishing makes a job complete.
func (p *scanProgress) percent() int64 {
	if p.listingsInFlight.Load() > 0 || p.countFailed.Load() {
		return 0
	}

	total := p.bytesTotal.Load()
	if total == 0 {
		return 0
	}

	return int64(min(p.bytesDone.Load()*100/total, 99))
}

// countBucket walks the bucket once, summing object count and size. Keys at or before startAfter are also
// counted as done, so a resumed scan starts its bar where the previous run stopped. Nothing is retained per object.
//
// The caller must increment listingsInFlight before starting it,
// so that percent never divides by a total that is still being counted.
func (s *Source) countBucket(ctx context.Context, client *s3.Client, bucket string, startAfter *string) {
	defer s.progress.listingsInFlight.Add(-1)

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// Cancellation means the scan ended first, which is not a count failure.
			if ctx.Err() != nil {
				return
			}
			s.progress.countFailed.Store(true)
			ctx.Logger().V(2).Info("could not count objects for progress", "bucket", bucket, "err", err)
			return
		}

		var objects, bytes, doneObjects, doneBytes uint64
		for _, obj := range page.Contents {
			size := uint64(max(*obj.Size, 0))
			objects++
			bytes += size
			if startAfter != nil && *obj.Key <= *startAfter {
				doneObjects++
				doneBytes += size
			}
		}
		s.progress.addTotal(objects, bytes)
		s.progress.addDone(doneObjects, doneBytes)
	}
	s.publishProgress()
}

// objectDone records that an object has been scanned or skipped.
func (s *Source) objectDone(size int64) {
	s.progress.addDone(1, uint64(max(size, 0)))
	s.publishProgress()
}

func (s *Source) publishProgress() {
	s.SetProgressPercent(
		s.progress.percent(),
		clampInt32(s.progress.objectsDone.Load()),
		clampInt32(s.progress.objectsTotal.Load()),
		progressMessage,
	)
}

func clampInt32(v uint64) int32 {
	return int32(min(v, math.MaxInt32))
}
