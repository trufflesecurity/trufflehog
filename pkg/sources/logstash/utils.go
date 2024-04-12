package logstash

import (
	"encoding/json"
	"io"
)

func bodyToJSON(r io.Reader) (map[string]any, error) {
	resBody, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	data := make(map[string]any)

	err = json.Unmarshal(resBody, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
