package sources

import "encoding/json"

// UnmarshalUnit is a helper function to JSON unmarshal an encoded unit into a concrete type T.
func UnmarshalUnit[T any](data []byte) (*T, error) {
	var unit T
	if err := json.Unmarshal(data, &unit); err != nil {
		return nil, err
	}
	return &unit, nil
}
