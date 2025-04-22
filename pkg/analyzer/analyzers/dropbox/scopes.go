package dropbox

import (
	"encoding/json"
	"errors"
)

type PermissionStatus string

const (
	// Scope Granted Status
	StatusGranted    PermissionStatus = "Granted"
	StatusDenied     PermissionStatus = "Denied"
	StatusUnverified PermissionStatus = "Unverified"
)

//go:embed scopes.json
var scopeConfigJson []byte

func getScopeConfigMap() (*scopeConfig, error) {
	var scopeConfigMap scopeConfig
	if err := json.Unmarshal(scopeConfigJson, &scopeConfigMap); err != nil {
		return nil, errors.New("failed to unmarshal scopes.json: " + err.Error())
	}
	return &scopeConfigMap, nil
}
