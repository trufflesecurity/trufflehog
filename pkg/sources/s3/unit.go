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
	// if a role is specified, we include it in the ID
	if s.Role != "" {
		return s.Role + "/" + s.Bucket, SourceUnitKindBucket
	}

	// otherwise just return the bucket name
	return s.Bucket, SourceUnitKindBucket
}

func (s S3SourceUnit) Display() string {
	id, _ := s.SourceUnitID()
	return id
}
