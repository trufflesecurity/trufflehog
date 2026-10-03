package s3

import (
	"fmt"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceUnitKindBucket sources.SourceUnitKind = "bucket"

// unitIDSeparator joins the role and bucket halves of a unit ID. It appears in
// neither a role ARN nor an S3 bucket name, so splitting on it is unambiguous.
const unitIDSeparator = "|"

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
		unitID += role + unitIDSeparator
	}
	return unitID + bucket
}

// unitEnvelope is the JSON shape a host application persists for an
// enumerated unit between an enumerate pass and a later scan pass: the
// SourceUnit proto marshalled with encoding/json, where unit_data carries the
// original unit as base64-encoded bytes.
type unitEnvelope struct {
	ID       string `json:"id"`
	Kind     string `json:"kind,omitempty"`
	Display  string `json:"display,omitempty"`
	UnitData string `json:"unit_data,omitempty"`
}

// splitS3SourceUnitID reverses constructS3SourceUnitID.
func splitS3SourceUnitID(unitID string) (role, bucket string) {
	if idx := strings.Index(unitID, unitIDSeparator); idx >= 0 {
		return unitID[:idx], unitID[idx+1:]
	}
	return "", unitID
}
