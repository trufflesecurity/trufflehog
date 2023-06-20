package sources

// CommonSourceUnit is a common implementation of SourceUnit that Sources can
// use instead of implementing their own types.
type CommonSourceUnit struct {
	ID string `json:"source_unit_id"`
}

// Implement the SourceUnit interface.
func (c CommonSourceUnit) SourceUnitID() string {
	return c.ID
}
