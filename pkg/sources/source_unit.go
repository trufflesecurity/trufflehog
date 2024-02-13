package sources

import (
	"encoding/json"
	"fmt"
)

// Ensure CommonSourceUnit implements SourceUnit at compile time.
var _ SourceUnit = CommonSourceUnit{}

// CommonSourceUnit is a common implementation of SourceUnit that Sources can
// use instead of implementing their own types.
type CommonSourceUnit struct {
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id"`
}

// SourceUnitID implements the SourceUnit interface.
func (c CommonSourceUnit) SourceUnitID() string {
	kind := "unit"
	if c.Kind != "" {
		kind = c.Kind
	}
	return fmt.Sprintf("%s:%s", kind, c.ID)
}

func (c CommonSourceUnit) Display() string {
	return c.ID
}

// CommonSourceUnitUnmarshaller is an implementation of SourceUnitUnmarshaller
// for the CommonSourceUnit. A source can embed this struct to gain the
// functionality of converting []byte to a CommonSourceUnit.
type CommonSourceUnitUnmarshaller struct{}

// UnmarshalSourceUnit implements the SourceUnitUnmarshaller interface.
func (c CommonSourceUnitUnmarshaller) UnmarshalSourceUnit(data []byte) (SourceUnit, error) {
	var unit CommonSourceUnit
	if err := json.Unmarshal(data, &unit); err != nil {
		return nil, err
	}
	if unit.ID == "" {
		return nil, fmt.Errorf("not a CommonSourceUnit")
	}
	return unit, nil
}

func IntoUnit[T any](unit SourceUnit) (T, error) {
	tUnit, ok := unit.(T)
	if !ok {
		var t T
		return t, fmt.Errorf("unsupported unit type: %T", unit)
	}
	return tUnit, nil
}

func IntoCommonUnit(unit SourceUnit) (CommonSourceUnit, error) {
	return IntoUnit[CommonSourceUnit](unit)
}
