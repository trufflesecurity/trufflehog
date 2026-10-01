package s3

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// directoryBucketSuffix ends every S3 Express directory bucket name, and AWS reserves it for them.
const directoryBucketSuffix = "--x-s3"

// listInputs returns the listings that cover what a scan of the bucket can include: one per include
// prefix, so S3 skips the keys outside them, or one of the whole bucket.
//
// The include prefixes are sorted and none starts with another, so listing them in turn returns keys
// in ascending order, just as one listing of the bucket would. That keeps the checkpoint a single
// start-after key, and passing it to every listing resumes exactly where the scan stopped: S3
// returns nothing for the prefixes the scan already finished.
func (s *Source) listInputs(bucket string, startAfter *string) []*s3.ListObjectsV2Input {
	prefixes := s.objectFilter.listPrefixes()
	// Directory buckets only accept a prefix that ends in "/", so they are listed whole and filtered after.
	if len(prefixes) == 0 || strings.HasSuffix(bucket, directoryBucketSuffix) {
		return []*s3.ListObjectsV2Input{{Bucket: &bucket, StartAfter: startAfter}}
	}

	inputs := make([]*s3.ListObjectsV2Input, len(prefixes))
	for i, prefix := range prefixes {
		inputs[i] = &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: aws.String(prefix), StartAfter: startAfter}
	}
	return inputs
}

// bucketPaginator pages through several listings in turn, as if they were one.
type bucketPaginator struct {
	client *s3.Client
	// inputs[0] is the listing in progress, and the rest are still to come.
	inputs []*s3.ListObjectsV2Input
	pages  *s3.ListObjectsV2Paginator
}

// newBucketPaginator starts with the first of inputs, which must not be empty.
func newBucketPaginator(client *s3.Client, inputs []*s3.ListObjectsV2Input) *bucketPaginator {
	return &bucketPaginator{client: client, inputs: inputs, pages: s3.NewListObjectsV2Paginator(client, inputs[0])}
}

// HasMorePages reports whether any listing has pages left, moving on to the next listing when the
// current one is done.
func (p *bucketPaginator) HasMorePages() bool {
	for !p.pages.HasMorePages() {
		if len(p.inputs) == 1 {
			return false
		}
		p.inputs = p.inputs[1:]
		p.pages = s3.NewListObjectsV2Paginator(p.client, p.inputs[0])
	}
	return true
}

// NextPage returns the next page of the current listing.
func (p *bucketPaginator) NextPage(ctx context.Context) (*s3.ListObjectsV2Output, error) {
	page, err := p.pages.NextPage(ctx)
	if err != nil && p.inputs[0].Prefix != nil {
		// A policy can allow listing some prefixes and not others, so say which one failed.
		err = fmt.Errorf("could not list prefix %q: %w", *p.inputs[0].Prefix, err)
	}
	return page, err
}
