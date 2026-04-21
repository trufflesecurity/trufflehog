package s3

import (
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceUnitKindBucket sources.SourceUnitKind = "bucket"

type S3SourceUnit struct {
	Bucket string
	Role   string
}

var _ sources.SourceUnit = S3SourceUnit{}

func (s S3SourceUnit) SourceUnitID() (string, sources.SourceUnitKind) {
	// ID is a combination of bucket and role (if any)
	return constructS3SourceUnitID(s.Bucket, s.Role), SourceUnitKindBucket
}

func (s S3SourceUnit) Display() string {
	if s.Role != "" {
		return fmt.Sprintf("Role=%s Bucket=%s", s.Role, s.Bucket)
	}
	return s.Bucket
}

func constructS3SourceUnitID(bucket string, role string) string {
	unitID := ""
	if role != "" {
		unitID += role + "|"
	}
	return unitID + bucket
}
