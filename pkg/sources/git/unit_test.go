package git

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalUnit(t *testing.T) {
	s := `{"kind":"repo","id":"https://github.com/trufflesecurity/test_keys.git"}`
	expectedUnit := SourceUnit{ID: "https://github.com/trufflesecurity/test_keys.git", Kind: UnitRepo}
	gotUnit, err := UnmarshalUnit([]byte(s))
	assert.NoError(t, err)

	assert.Equal(t, expectedUnit, gotUnit)

	_, err = UnmarshalUnit(nil)
	assert.Error(t, err)

	_, err = UnmarshalUnit([]byte(`{"kind":"idk","id":"id"}`))
	assert.Error(t, err)
}

func TestMarshalUnit(t *testing.T) {
	unit := SourceUnit{ID: "https://github.com/trufflesecurity/test_keys.git", Kind: UnitRepo}
	b, err := json.Marshal(unit)
	assert.NoError(t, err)

	assert.Equal(t, `{"kind":"repo","id":"https://github.com/trufflesecurity/test_keys.git"}`, string(b))
}

func TestDisplayUnit(t *testing.T) {
	unit := SourceUnit{ID: "https://github.com/trufflesecurity/test_keys.git", Kind: UnitRepo}
	assert.Equal(t, "trufflesecurity/test_keys", unit.Display())

	unit = SourceUnit{ID: "/path/to/repo", Kind: UnitDir}
	assert.Equal(t, "repo", unit.Display())

	unit = SourceUnit{ID: "ssh://github.com/trufflesecurity/test_keys", Kind: UnitRepo}
	assert.Equal(t, "trufflesecurity/test_keys", unit.Display())
}
