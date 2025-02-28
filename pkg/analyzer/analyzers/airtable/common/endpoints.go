package common

type ErrorResponse struct {
	Type string
}

type Endpoint struct {
	URL                   string
	Method                string
	RequiredIDs           []string
	RequiredPermission    *string
	ExpectedErrorResponse *ErrorResponse
}

type EndpointName int

const (
	GetUserInfoEndpoint            EndpointName = iota
	ListBasesEndpoint              EndpointName = iota
	UpdateBaseEndpoint             EndpointName = iota
	GetBaseSchemaEndpoint          EndpointName = iota
	ListRecordsEndpoint            EndpointName = iota
	CreateRecordEndpoint           EndpointName = iota
	ListRecordCommentsEndpoint     EndpointName = iota
	ListWebhooksEndpoint           EndpointName = iota
	ListBlockInstallationsEndpoint EndpointName = iota
)

func GetRequiredPermission(permission Permission) *string {
	if val, exists := PermissionStrings[permission]; exists {
		return &val
	}
	return nil
}

var Endpoints = map[EndpointName]Endpoint{
	GetUserInfoEndpoint: {
		URL:    "https://api.airtable.com/v0/meta/whoami",
		Method: "GET",
	},
	ListBasesEndpoint: {
		URL:                "https://api.airtable.com/v0/meta/bases",
		Method:             "GET",
		RequiredPermission: GetRequiredPermission(SchemaBasesRead),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
	UpdateBaseEndpoint: {
		URL:                "https://api.airtable.com/v0/meta/bases/{baseID}/tables/{tableID}",
		Method:             "PATCH",
		RequiredIDs:        []string{"baseID", "tableID"},
		RequiredPermission: GetRequiredPermission(SchemaBasesWrite),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
	GetBaseSchemaEndpoint: {
		URL:                "https://api.airtable.com/v0/meta/bases/{baseID}/tables",
		Method:             "GET",
		RequiredIDs:        []string{"baseID"},
		RequiredPermission: GetRequiredPermission(SchemaBasesRead),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
	ListRecordsEndpoint: {
		URL:                "https://api.airtable.com/v0/{baseID}/{tableID}",
		Method:             "GET",
		RequiredIDs:        []string{"baseID", "tableID"},
		RequiredPermission: GetRequiredPermission(DataRecordsRead),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
	CreateRecordEndpoint: {
		URL:                "https://api.airtable.com/v0/{baseID}/{tableID}",
		Method:             "POST",
		RequiredIDs:        []string{"baseID", "tableID"},
		RequiredPermission: GetRequiredPermission(DataRecordsWrite),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
	ListRecordCommentsEndpoint: {
		URL:                "https://api.airtable.com/v0/{baseID}/{tableID}/{recordID}/comments",
		Method:             "GET",
		RequiredIDs:        []string{"baseID", "tableID", "recordID"},
		RequiredPermission: GetRequiredPermission(DataRecordcommentsRead),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
	ListWebhooksEndpoint: {
		URL:                "https://api.airtable.com/v0/bases/{baseID}/webhooks",
		Method:             "GET",
		RequiredIDs:        []string{"baseID"},
		RequiredPermission: GetRequiredPermission(WebhookManage),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
	ListBlockInstallationsEndpoint: {
		URL:                "https://api.airtable.com/v0/meta/bases/{baseID}/blockInstallations",
		Method:             "GET",
		RequiredIDs:        []string{"baseID"},
		RequiredPermission: GetRequiredPermission(BlockManage),
		ExpectedErrorResponse: &ErrorResponse{
			Type: "INVALID_PERMISSIONS_OR_MODEL_NOT_FOUND",
		},
	},
}
