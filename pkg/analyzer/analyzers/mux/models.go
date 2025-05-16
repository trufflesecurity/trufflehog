package mux

import (
	"fmt"
	"net/http"
)

type ResourceType string

const (
	ResourceTypeVideo  ResourceType = "video"
	ResourceTypeData   ResourceType = "data"
	ResourceTypeSystem ResourceType = "system"
)

type permissionTestConfig struct {
	Tests []permissionTest `json:"tests"`
}

type permissionTest struct {
	ResourceType    ResourceType `json:"resource_type"`
	Permission      string       `json:"permission"`
	Endpoint        string       `json:"endpoint"`
	Method          string       `json:"method"`
	ValidStatusCode int          `json:"valid_status_code"`
}

func (test permissionTest) testPermission(client *http.Client, key string, secret string) (bool, error) {
	_, statusCode, err := makeAPIRequest(client, key, secret, test.Method, test.Endpoint)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case test.ValidStatusCode:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

type secretInfo struct {
	Permissions map[ResourceType]Permission
	Assets      []asset
	Annotations []annotation
	SigningKeys []signingKey
}

func (info *secretInfo) addPermission(resourceType ResourceType, permission string) {
	if info.Permissions == nil {
		info.Permissions = map[ResourceType]Permission{}
	}
	if perm := info.Permissions[resourceType]; perm == FullAccess {
		return
	}

	if permission == "read" {
		info.Permissions[resourceType] = Read
	} else if permission == "write" {
		info.Permissions[resourceType] = FullAccess
	}
}

func (info *secretInfo) hasPermission(resourceType ResourceType, permission Permission) bool {
	perm, exists := info.Permissions[resourceType]
	if !exists {
		return false
	}
	return perm == permission || perm == FullAccess
}

// Resource structs

type track struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Duration float64 `json:"duration"`
	Status   string  `json:"status"`
	Primary  bool    `json:"primary"`

	TextType     string `json:"text_type"`
	TextSource   string `json:"text_source"`
	LanguageCode string `json:"language_code"`

	MaxWidth     int     `json:"max_width"`
	MaxHeight    int     `json:"max_height"`
	MaxFrameRate float64 `json:"max_frame_rate"`
	MaxChannels  int     `json:"max_channels"`
}

type playbackID struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type meta struct {
	Title      string `json:"title"`
	ExternalID string `json:"external_id"`
	CreatorID  string `json:"creator_id"`
}

type asset struct {
	ID           string       `json:"id"`
	Duration     float64      `json:"duration"`
	Status       string       `json:"status"`
	VideoQuality string       `json:"video_quality"`
	MP4Support   string       `json:"mp4_support"`
	AspectRatio  string       `json:"aspect_ratio"`
	Tracks       []track      `json:"tracks"`
	PlaybackIDs  []playbackID `json:"playback_ids"`
	Meta         meta         `json:"meta"`
	CreatedAt    string       `json:"created_at"`
}

type annotation struct {
	SubPropertyID string `json:"sub_property_id"`
	Note          string `json:"note"`
	ID            string `json:"id"`
	Date          string `json:"date"`
}

type signingKey struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}

// API response structs

type assetListResponse struct {
	Data []asset `json:"data"`
}

type annotationListResponse struct {
	Data []annotation `json:"data"`
}

type signingKeyListResponse struct {
	Data []signingKey `json:"data"`
}
