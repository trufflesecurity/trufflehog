package postman

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

type PostmanKeyValue struct {
	Key   string
	Value string
}

type PostmanAuth struct {
	Type   string
	Apikey []PostmanKeyValue
	Bearer []PostmanKeyValue
	AWSv4  []PostmanKeyValue
	Basic  []PostmanKeyValue
	OAuth2 []PostmanKeyValue
}

type PostmanUrl struct {
	Raw      string
	Protocol string
	Host     []string
	Path     []string
	Query    []PostmanKeyValue
}

type PostmanBody struct {
	Mode       string
	Raw        string
	File       PostmanBodyFile
	UrlEncoded []PostmanKeyValue
	FormData   []PostmanKeyValue
	GraphQL    PostmanBodyGraphQL
}

type PostmanBodyGraphQL struct {
	Query     string
	Variables string
}

type PostmanBodyFile struct {
	Src string
}

type PostmanRequest struct {
	Auth            PostmanAuth
	Method          string
	HeaderStrings   []string
	HeaderKeyValues []PostmanKeyValue
	Body            PostmanBody
	Url             PostmanUrl
	Description     string
}
