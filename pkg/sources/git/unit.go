package git

import (
	"encoding/json"
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	UnitRepo string = "repo"
	UnitDir  string = "dir"
)

// Ensure SourceUnit implements the interface at compile time.
var _ sources.SourceUnit = SourceUnit{}

// A git source unit can be two kinds of units: either a local directory path
// or a remote repository.
type SourceUnit struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Implement sources.SourceUnit interface.
func (u SourceUnit) SourceUnitID() string {
	return u.ID
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
