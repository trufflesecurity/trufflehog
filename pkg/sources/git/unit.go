package git

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	UnitRepo sources.SourceUnitKind = "repo"
	UnitDir  sources.SourceUnitKind = "dir"
)

// Ensure SourceUnit implements the interface at compile time.
var _ sources.SourceUnit = SourceUnit{}

// A git source unit can be two kinds of units: either a local directory path
// or a remote repository.
type SourceUnit struct {
	Kind sources.SourceUnitKind `json:"kind"`
	ID   string                 `json:"id"`
}

// Implement sources.SourceUnit interface.
func (u SourceUnit) SourceUnitID() (string, sources.SourceUnitKind) {
	return u.ID, u.Kind
}

// Provide a custom Display method.
func (u SourceUnit) Display() string {
	switch u.Kind {
	case UnitRepo:
		repo := u.ID
		if parsedURL, err := url.Parse(u.ID); err == nil {
			// scheme://host/owner/repo
			repo = strings.TrimPrefix(parsedURL.Path, "/")
		} else if _, path, found := strings.Cut(u.ID, ":"); found {
			// git@host:owner/repo
			// TODO: Is this possible? We should maybe canonicalize
			// the URL before getting here.
			repo = path
		}
		return strings.TrimSuffix(repo, ".git")
	case UnitDir:
		return filepath.Base(u.ID)
	default:
		return "mysterious git unit"
	}
}

// Helper function to unmarshal raw bytes into our SourceUnit struct.
func UnmarshalUnit(data []byte) (sources.SourceUnit, error) {
	var unit SourceUnit
	if err := json.Unmarshal(data, &unit); err != nil {
		return nil, err
	}
	if unit.ID == "" || (unit.Kind != UnitRepo && unit.Kind != UnitDir) {
		return nil, fmt.Errorf("not a git.SourceUnit")
	}
	return unit, nil
}
