package figma

import (
	"errors"
	"net/http"
)

type EndpointName int

const (
	GetUserInfo EndpointName = iota
	GetLibraryComponentAction
	PostFileDevResources
	GetFileVariables
	PostWebhook
	GetProjects
	GetFiles
	PostFileVariables
	PostFileComment
)

var endpointMessagesWithScope = map[EndpointName]string{
	GetLibraryComponentAction: "Not found",
	PostFileDevResources:      "Missing required parameter dev_resources",
	GetFileVariables:          "Not found",
	PostWebhook:               "Missing required parameter team_id",
	GetProjects:               "No such team",
	PostFileVariables:         "Missing required parameter dev_resources",
	PostFileComment:           "Missing required parameter message_meta",
}

var endpointMessagesWithoutScope = map[EndpointName]string{
	GetUserInfo:               `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_read or files:read or me scope\.?`,
	GetLibraryComponentAction: `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the library_analytics:read scope\.?`,
	PostFileDevResources:      `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_read or file_dev_resources:write scope\.?`,
	GetFileVariables:          `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_read or file_variables:read scope\.?`,
	PostWebhook:               `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_read or webhooks:write scope\.?`,
	GetProjects:               `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_read or files:read or projects:read scope\.?`,
	GetFiles:                  `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_read or files:read or projects:read scope\.?`,
	PostFileVariables:         `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_variables:write scope\.?`,
	PostFileComment:           `^Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires the file_read or file_comments:write scope\.?`,
}

var endpoints map[EndpointName]Endpoint

func init() {
	endpoints = map[EndpointName]Endpoint{
		GetUserInfo: {
			URL:    "https://api.figma.com/v1/me",
			Method: http.MethodGet,
			ExpectedResponseWithScope: APIErrorResponse{
				Status: http.StatusOK,
			},
			ExpectedResponseWithoutScope: APIErrorResponse{
				Status:  http.StatusForbidden,
				Message: getEndpointMessageWithoutScope(GetUserInfo),
			},
		},
		GetLibraryComponentAction: {
			URL:    "https://api.figma.com/v1/analytics/libraries/0/component/actions",
			Method: http.MethodGet,
			ExpectedResponseWithScope: APIErrorResponse{
				Status:  http.StatusBadRequest,
				Message: getEndpointMessageWithScope(GetLibraryComponentAction),
			},
			ExpectedResponseWithoutScope: APIErrorResponse{
				Status:  http.StatusForbidden,
				Message: getEndpointMessageWithoutScope(GetLibraryComponentAction),
			},
		},
		PostFileDevResources: {
			URL:    "https://api.figma.com/v1/dev_resources",
			Method: http.MethodPost,
			ExpectedResponseWithScope: APIErrorResponse{
				Status:  http.StatusBadRequest,
				Message: getEndpointMessageWithScope(PostFileDevResources),
			},
			ExpectedResponseWithoutScope: APIErrorResponse{
				Status:  http.StatusForbidden,
				Message: getEndpointMessageWithoutScope(PostFileDevResources),
			},
		},
		GetFileVariables: {
			URL:    "https://api.figma.com/v1/files/0/variables/published",
			Method: http.MethodGet,
			ExpectedResponseWithScope: APIErrorResponse{
				Status:  http.StatusNotFound,
				Message: getEndpointMessageWithScope(GetFileVariables),
			},
			ExpectedResponseWithoutScope: APIErrorResponse{
				Status:  http.StatusForbidden,
				Message: getEndpointMessageWithoutScope(GetFileVariables),
			},
		},
		PostWebhook: {
			URL:    "https://api.figma.com/v2/webhooks",
			Method: http.MethodPost,
			ExpectedResponseWithScope: APIErrorResponse{
				Status:  http.StatusBadRequest,
				Message: getEndpointMessageWithScope(PostWebhook),
			},
			ExpectedResponseWithoutScope: APIErrorResponse{
				Status: http.StatusForbidden,
				Err:    getEndpointMessageWithoutScope(PostWebhook),
			},
		},
		GetProjects: {
			URL:    "https://api.figma.com/v1/teams/0/projects",
			Method: http.MethodPost,
			ExpectedResponseWithScope: APIErrorResponse{
				Status:  http.StatusBadRequest,
				Message: getEndpointMessageWithScope(GetProjects),
			},
			ExpectedResponseWithoutScope: APIErrorResponse{
				Status: http.StatusForbidden,
				Err:    getEndpointMessageWithoutScope(PostWebhook),
			},
		},
	}
}

func getEndpointMessageWithScope(endpointName EndpointName) string {
	return endpointMessagesWithScope[endpointName]
}

func getEndpointMessageWithoutScope(endpointName EndpointName) string {
	return endpointMessagesWithoutScope[endpointName]
}

// getEndpoint returns the endpoint object for the provided name or an error
func getEndpoint(name EndpointName) (Endpoint, error) {
	if endpoint, ok := endpoints[name]; ok {
		return endpoint, nil
	}
	return Endpoint{}, errors.New("invalid name or endpoint doesn't exist")
}
