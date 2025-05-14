package postman

import "github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"

// TODO - Verify that all these fields are populated
type PostmanWorkspaceSummary struct {
	Id   string
	Name string
}
type PostmanWorkspace struct {
	Id        string
	Name      string
	CreatedBy string

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

	Auth      PostmanCollectionAuth
	Variables []struct {
		Key   string
		Value string
	}
	Events []PostmanCollectionEvent

	Items []PostmanCollectionItem
}

type PostmanCollectionItem struct {
	Name string
	Id   string
	Uid  string

	Request   PostmanCollectionRequest
	Responses []PostmanCollectionResponse
	Events    []PostmanCollectionEvent
	Auth      PostmanCollectionAuth

	Items []PostmanCollectionItem
}

type PostmanCollectionResponse struct {
	Uid  string
	Body string

	OriginalRequest PostmanCollectionRequest

	Headers []struct {
		Key   string
		Value string
	}
}

type PostmanCollectionRequest struct {
	Method  string
	Url     PostmanCollectionUrl
	Auth    PostmanCollectionAuth
	Body    PostmanRequestBody
	Headers []struct {
		Key   string
		Value string
	}
}

type PostmanRequestBody struct {
	Mode string
	Raw  string

	GraphQl struct {
		Query     string
		Variables string
	}
	FormData []struct {
		Key   string
		Value string
	}
	UrlEncoded []struct {
		Key   string
		Value string
	}
}

type PostmanCollectionEvent struct {
	Listen string

	Script struct {
		Exec []string
	}
}

type PostmanCollectionUrl struct {
	Raw      string
	Protocol string
	Host     []string
	Path     []string
	Query    []struct {
		Key   string
		Value string
	}
}

type PostmanCollectionAuth struct {
	Type   string
	ApiKey []struct {
		Key   string
		Value string
	}
	AwsV4 []struct {
		Key   string
		Value string
	}
	Bearer []struct {
		Key   string
		Value string
	}
	Basic []struct {
		Key   string
		Value string
	}
	OAuth2 []struct {
		Key   string
		Value string
	}
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
		Key          string
		Value        string
		SessionValue string
	}
}

type PostmanMetadata struct {
	fromLocal    bool
	LocationType source_metadatapb.PostmanLocationType

	Type      string
	FieldType string
	Link      string

	WorkspaceId     string
	WorkspaceName   string
	EnvironmentUid  string
	EnvironmentName string
	CollectionUid   string
	CollectionName  string
	FolderUid       string
	FolderName      string
	RequestUid      string
	RequestName     string
}
