package s3

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceUnitKindBucket sources.SourceUnitKind = "bucket"

type S3SourceUnit struct {
	Bucket string
	Role   string
}

var _ sources.SourceUnit = S3SourceUnit{}

func (s S3SourceUnit) SourceUnitID() (string, sources.SourceUnitKind) {
	// The ID is the bucket name, and the kind is "bucket".
	return s.Bucket, SourceUnitKindBucket
}

func (s S3SourceUnit) Display() string {
	return s.Bucket
}
