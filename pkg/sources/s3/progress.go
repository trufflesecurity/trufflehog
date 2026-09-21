package s3

import (
	"math"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

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

	// countIncomplete is set when a count pass ended before listing its whole bucket, whether it failed
	// or was cancelled, leaving totals too low to divide by.
	countIncomplete atomic.Bool
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
	if p.listingsInFlight.Load() > 0 || p.countIncomplete.Load() {
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
	var counted bool

	// Publish after the decrement, because percent reports nothing while a count is in flight. Without it
	// the bar stays at 0 until the next object finishes, which for large objects is minutes.
	defer func() {
		if !counted {
			s.objectProgress.countIncomplete.Store(true)
		}
		s.objectProgress.listingsInFlight.Add(-1)
		s.publishProgress()
	}()

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &bucket})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// Cancellation means the scan ended first, so the pages already counted stay unusable rather
			// than becoming a total the rest of the scan divides by.
			if ctx.Err() == nil {
				ctx.Logger().V(2).Info("could not count objects for progress", "bucket", bucket, "err", err)
			}
			return
		}

		var objects, bytes, doneObjects, doneBytes uint64
		for _, obj := range page.Contents {
			if !s.countsTowardProgress(obj) {
				continue
			}
			size := uint64(max(*obj.Size, 0))
			objects++
			bytes += size
			if startAfter != nil && *obj.Key <= *startAfter {
				doneObjects++
				doneBytes += size
			}
		}
		s.objectProgress.addTotal(objects, bytes)
		s.objectProgress.addDone(doneObjects, doneBytes)
	}
	counted = true
}

// countsTowardProgress reports whether an object belongs in the progress ratio. Objects this scan will
// never download are left out of both the total and the done count, so that the percent tracks the bytes
// actually fetched rather than jumping whenever a skipped object goes by.
//
// The order of the tests mirrors pageChunker, which checks the object filter before anything else and
// counts what the filter skips as done. A filtered object therefore belongs in the total as well,
// whatever its storage class or size, or the done count would climb past a total it was never in.
func (s *Source) countsTowardProgress(obj s3types.Object) bool {
	if !s.objectFilter.shouldInclude(*obj.Key) {
		return true
	}
	if obj.StorageClass == s3types.ObjectStorageClassGlacier || obj.StorageClass == s3types.ObjectStorageClassGlacierIr {
		return false
	}
	return *obj.Size <= s.maxObjectSize
}

// objectDone records that an object has been scanned or skipped.
func (s *Source) objectDone(size int64) {
	s.objectProgress.addDone(1, uint64(max(size, 0)))
	s.publishProgress()
}

func (s *Source) publishProgress() {
	s.SetProgressPercent(
		s.objectProgress.percent(),
		clampInt32(s.objectProgress.objectsDone.Load()),
		clampInt32(s.objectProgress.objectsTotal.Load()),
		progressMessage,
	)
}

func clampInt32(v uint64) int32 {
	return int32(min(v, math.MaxInt32))
}
