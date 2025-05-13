package postman

import "github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"

// TODO - Move these into postman/common.go or similar
// TODO - Verify that all these fields are populated
type PostmanWorkspaceSummary struct {
	Id   string
	Name string
}
type PostmanWorkspace struct {
	Id                   string
	Name                 string
	CreatedBy            string
	CollectionSummaries  []PostmanCollectionSummary
	EnvironmentSummaries []PostmanEnvironmentSummary
}
type PostmanCollectionSummary struct {
	Id   string
	Name string
	Uid  string
}
type PostmanCollection struct {
	Uid  string
	Name string
}
type PostmanEnvironmentSummary struct {
	Id   string
	Name string
	Uid  string
}
type PostmanEnvironment struct {
	Uid       string
	Id        string
	Name      string
	KeyValues []struct {
		Key   string
		Value string
	}
}

type PostmanMetadata struct {
	fromLocal    bool
	LocationType source_metadatapb.PostmanLocationType

	Type string
	Link string

	CollectionUid  string
	CollectionName string
}
