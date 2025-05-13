package postman

import (
	"encoding/json"
	"fmt"
	"github.com/repeale/fp-go"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/volatiletech/null/v8"
	"golang.org/x/time/rate"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	POSTMAN_API_BASE_URL = "https://api.postman.com"
)

// *****************************************************
// *****************************************************
// Primary Exported Objects
// *****************************************************
// *****************************************************

// *****************************************************
// *****************************************************
// Internal Use Only Response Objects
// *****************************************************
// *****************************************************

// PostmanApiResponse_GetWorkspaceListResponse_200
// *****************************************************
// GET /workspaces Response Objects
//
// Based on the documentation here:
// https://www.postman.com/postman/postman-public-workspace/documentation/i2uqzpp/postman-api?entity=request-f027a0fa-9012-4654-a65d-2b751a3154a9
// *****************************************************
type PostmanApiResponse_GetWorkspaceListResponse_200 struct {
	Workspaces []struct {
		Id         string `json:"id"`
		Name       string `json:"name"`
		CreatedBy  string `json:"created_by"`
		Type       string `json:"type"`
		Visibility string `json:"visibility"`
	} `json:"workspaces"`
}
type PostmanApiResponse_GetWorkspaceListResponse_401 struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}
type PostmanApiResponse_GetWorkspaceListResponse_429 struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// PostmanApiResponse_GetWorkspaceResponse_200
// *****************************************************
// GET /workspaces/{UID}
//
// Based on the documentation here:
// https://www.postman.com/postman/postman-public-workspace/documentation/i2uqzpp/postman-api?entity=request-3a56b6f8-8d0c-410f-a933-03e26589c742
// *****************************************************
type PostmanApiResponse_GetWorkspaceResponse_200 struct {
	Workspace struct {
		Id          string `json:"id"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Visibility  string `json:"visibility"`
		CreatedBy   string `json:"createdBy"`
		UpdatedBy   string `json:"updatedBy"`
		CreatedAt   string `json:"createdAt"`
		UpdatedAt   string `json:"updatedAt"`
		Collections []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
			Uid  string `json:"uid"`
		} `json:"collections"`
		Environments []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
			Uid  string `json:"uid"`
		} `json:"environments"`
		Mocks []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			Uid         string `json:"uid"`
			Deactivated bool   `json:"deactivated"`
		} `json:"mocks"`
		Monitors []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			Uid         string `json:"uid"`
			Deactivated bool   `json:"deactivated"`
		} `json:"monitors"`
		Apis []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
			Uid  string `json:"uid"`
		} `json:"apis"`
		Scim struct {
			CreatedBy string `json:"createdBy"`
			UpdatedBy string `json:"updatedBy"`
		} `json:"scim"`
	} `json:"workspace"`
}
type PostmanApiResponse_GetWorkspaceResponse_401 struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}
type PostmanApiResponse_GetWorkspaceResponse_403 struct {
	Error struct {
		Name       string `json:"name"`
		Message    string `json:"message"`
		StatusCode string `json:"statusCode"`
	} `json:"error"`
}
type PostmanApiResponse_GetWorkspaceResponse_404 struct {
	Error struct {
		Name       string `json:"name"`
		Message    string `json:"message"`
		StatusCode int    `json:"status_code"`
	} `json:"error"`
}
type PostmanApiResponse_GetWorkspaceResponse_429 struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// PostmanApiResponse_GetCollectionResponse_200
// *****************************************************
// GET /collections/{UID}
//
// Based on the documentation here:
// https://www.postman.com/postman/postman-public-workspace/documentation/i2uqzpp/postman-api?entity=request-a6a282df-907e-438b-8fe6-e5efaa60b8bf
// *****************************************************
type PostmanApiResponse_GetCollectionResponse_200 struct {
	Collection struct {
		Info struct {
			PostmanId     string `json:"_postman_id"`
			Name          string `json:"name"`
			Description   string `json:"description"`
			Schema        string `json:"schema"`
			UpdatedAt     string `json:"updatedAt"`
			CreatedAt     string `json:"createdAt"`
			LastUpdatedBy string `json:"lastUpdatedBy"`
			Uid           string `json:"uid"`
		} `json:"collection"`
		Auth     PostmanApiResponse_GetCollectionResponse_Auth        `json:"auth"`
		Item     []PostmanApiResponse_GetCollectionResponse_Item      `json:"item"`
		Event    []PostmanApiResponse_GetCollectionResponse_ItemEvent `json:"event"`
		Variable []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"variable"`
	} `json:"collection"`
}
type PostmanApiResponse_GetCollectionResponse_401 struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}
type PostmanApiResponse_GetCollectionResponse_404 struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}
type PostmanApiResponse_GetCollectionResponse_429 struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type PostmanApiResponse_GetCollectionResponse_Header struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}
type PostmanApiResponse_GetCollectionResponse_ItemRequest struct {
	Auth   PostmanApiResponse_GetCollectionResponse_Auth     `json:"auth"`
	Method string                                            `json:"method"`
	Header []PostmanApiResponse_GetCollectionResponse_Header `json:"header"`
	Body   struct {
		Mode    string `json:"mode"`
		Raw     string `json:"raw"`
		Options struct {
			Raw struct {
				Language string `json:"language"`
			} `json:"raw"`
		} `json:"options"`
	} `json:"body"`
	Url struct {
		Raw      string   `json:"raw"`
		Protocol string   `json:"protocol"`
		Host     []string `json:"host"`
		Path     []string `json:"path"`
		Query    []struct {
			Key         string `json:"key"`
			Value       string `json:"value"`
			Description string `json:"description"`
		} `json:"query"`
	} `json:"url"`
}
type PostmanApiResponse_GetCollectionResponse_ItemEvent struct {
	Listen string `json:"listen"`
	Script struct {
		Type string   `json:"type"`
		Exec []string `json:"exec"`
	} `json:"script"`
}
type PostmanApiResponse_GetCollectionResponse_Item struct {
	Name                    string                                        `json:"name"`
	Id                      string                                        `json:"id"`
	Uid                     string                                        `json:"uid"`
	Description             string                                        `json:"description"`
	Auth                    PostmanApiResponse_GetCollectionResponse_Auth `json:"auth"`
	ProtocolProfileBehavior struct {
		DisableBodyPruning bool `json:"disableBodyPruning"`
	} `json:"protocolProfileBehavior"`
	Request  PostmanApiResponse_GetCollectionResponse_ItemRequest `json:"request"`
	Response []struct {
		Id                     string                                               `json:"id"`
		Uid                    string                                               `json:"uid"`
		Name                   string                                               `json:"name"`
		OriginalRequest        PostmanApiResponse_GetCollectionResponse_ItemRequest `json:"originalRequest"`
		Status                 string                                               `json:"status"`
		Code                   int8                                                 `json:"code"`
		PostmanPreviewLanguage string                                               `json:"_postman_previewlanguage"`
		Header                 PostmanApiResponse_GetCollectionResponse_Header      `json:"header"`
		Cookie                 []struct{}                                           `json:"cookie"`
		ResponseTime           null.String                                          `json:"responseTime"`
		Body                   string                                               `json:"body"`
	} `json:"response"`
	Item  []PostmanApiResponse_GetCollectionResponse_Item      `json:"item"`
	Event []PostmanApiResponse_GetCollectionResponse_ItemEvent `json:"event"`
}
type PostmanApiResponse_GetCollectionResponse_Auth struct {
	Type   string `json:"type"`
	ApiKey []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"apikey"`
}

// PostmanApiResponse_GetEnvironmentResponse_200
// *****************************************************
// GET /environments/{UID}
// *****************************************************
type PostmanApiResponse_GetEnvironmentResponse_200 struct {
	Environment struct {
		Id        string `json:"id"`
		Name      string `json:"name"`
		Owner     string `json:"owner"`
		CreatedAt string `json:"createdAt"`
		UpdatedAt string `json:"updatedAt"`
		Values    []struct {
			Key     string `json:"key"`
			Value   string `json:"value"`
			Enabled bool   `json:"enabled"`
			Type    string `json:"type"`
		} `json:"values"`
	} `json:"environment"`
}
type PostmanApiResponse_GetEnvironmentResponse_401 struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}
type PostmanApiResponse_GetEnvironmentResponse_404 struct {
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}
type PostmanApiResponse_GetEnvironmentResponse_429 struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// *****************************************************
// Our client object and interface itself
// *****************************************************

// This is intentionally not exported, to force clients to use the constructor, NewPostmanApiClient
type postmanApiClient struct {
	// HTTP client used to communicate with the API
	httpClient *http.Client

	// Headers to attach to every request made with the client.
	headers map[string]string

	// Governing rate limiters for this client
	clientRateLimiters struct {

		// Rate limiter needed for Postman API workspace and collection requests. Postman API rate limit
		// is 10 calls in 10 seconds for GET /collections, GET /workspaces, and GET /workspaces/{id} endpoints.
		workspaceAndCollectionRateLimiter *rate.Limiter

		// Rate limiter needed for Postman API. General rate limit is 300 requests per minute.
		generalRateLimiter *rate.Limiter
	}
}

func NewPostmanApiClient(postmanApiToken string) *postmanApiClient {
	return &postmanApiClient{
		httpClient: http.DefaultClient,
		headers: map[string]string{
			"Content-Type": "*",
			"User-Agent":   "PostmanRuntime/7.26.8",
			"X-API-Key":    postmanApiToken,
		},
		clientRateLimiters: struct {
			workspaceAndCollectionRateLimiter *rate.Limiter
			generalRateLimiter                *rate.Limiter
		}{workspaceAndCollectionRateLimiter: rate.NewLimiter(rate.Every(time.Second), 1),
			generalRateLimiter: rate.NewLimiter(rate.Every(time.Second/5), 1)},
	}
}

func (pc *postmanApiClient) waitForClientRateLimiters(ctx context.Context, request *http.Request) (bool, error) {

	// Depending on the request we're using, we select the appropriate rate limiter
	var limiter *rate.Limiter
	// todo - Tighten down this regex
	workspaceAndCollectionPathRegex, _ := regexp.Compile("collection|workspace")
	switch true {
	case workspaceAndCollectionPathRegex.MatchString(request.URL.Path):
		limiter = pc.clientRateLimiters.workspaceAndCollectionRateLimiter
	default:
		limiter = pc.clientRateLimiters.generalRateLimiter
	}

	// Now we do the actual wait
	err := limiter.Wait(ctx)
	if err != nil {
		return false, fmt.Errorf("error waiting for rate limiter in postman apiClient: %w", err)
	}

	// If we made it here, we're good
	return true, nil
}

// Handles all the mechanics of the request to the postman API, including rate limiting.  Returns with the
// request body as a byte slice, as well as the status code for the request
func (pc *postmanApiClient) getPostmanResponseBodyBytes(ctx context.Context, urlStr string) ([]byte, int, error) {
	// Make the request object
	request, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		// todo - when might we see this error
		return nil, 0, err
	}

	// Add in all the headers we care about
	for headerKey, headerValue := range pc.headers {
		request.Header.Set(headerKey, headerValue)
	}

	// Do the actual request
	response, err := pc.httpClient.Do(request)
	if err != nil {
		// todo - when might we see this error
		return nil, 0, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// todo - what should we do here?
		}
	}(response.Body)

	// Read in the body of the request
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("could not read postman response body: %w", err)
	}
	ctx.Logger().V(4).Info("postman api response headers:", "response_header", response.Header)

	return body, response.StatusCode, nil
}

// GetWorkspaceSummaryList
//
// Returns a list of workspaces that are accessible to the API key provided when this
// client was created.
func (pc *postmanApiClient) GetWorkspaceSummaryList(ctx context.Context) ([]PostmanWorkspaceSummary, error) {

	// Go make the request to the Postman API
	responseBody, statusCode, err := pc.getPostmanResponseBodyBytes(ctx, fmt.Sprintf("%s/workspaces", POSTMAN_API_BASE_URL))
	if err != nil {
		return nil, fmt.Errorf("could not get postman workspace summary list: %w", err)
	}

	// Figure out which response we're likely dealing with, and unmarshal based on that
	switch statusCode {
	case 200:
		// Go ahead and parse the response
		workspaceListResponse := PostmanApiResponse_GetWorkspaceListResponse_200{}
		if err := json.Unmarshal(responseBody, &workspaceListResponse); err != nil {
			return nil, fmt.Errorf("could not parse postman workspace summary list %d response: %w", statusCode, err)
		}

		// Now we shepherd the data we care about into our response
		summaries := make([]PostmanWorkspaceSummary, len(workspaceListResponse.Workspaces))
		for i, responseWorkspaceSummary := range workspaceListResponse.Workspaces {
			summaries[i] = PostmanWorkspaceSummary{
				Id:   responseWorkspaceSummary.Id,
				Name: responseWorkspaceSummary.Name,
			}
		}

		return summaries, nil
	case 401:
		workspaceListResponse := PostmanApiResponse_GetWorkspaceListResponse_401{}
		if err := json.Unmarshal(responseBody, &workspaceListResponse); err != nil {
			return nil, fmt.Errorf("could not parse postman workspace summary list %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 401 from the postman workspace summary list api",
			"postman_error_name", workspaceListResponse.Error.Name,
			"postman_error_message", workspaceListResponse.Error.Message)

		return nil, fmt.Errorf("postman workspace summary list api returned a 401 - do we have the right access?")
	case 429:
		workspaceListResponse := PostmanApiResponse_GetWorkspaceListResponse_429{}
		if err := json.Unmarshal(responseBody, &workspaceListResponse); err != nil {
			return nil, fmt.Errorf("could not parse postman summary list %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 429 from the postman workspace summary list api",
			"postman_error", workspaceListResponse.Error,
			"postman_error_message", workspaceListResponse.Message)

		return nil, fmt.Errorf("postman workspace summary list api returned a 429 - are too many scanners running against the postman api?")
	default:
		return nil, fmt.Errorf("postman workspace summary list endpoint returned unexpected status code: %d", statusCode)
	}
}

func (pc *postmanApiClient) GetWorkspaceById(ctx context.Context, id string) (PostmanWorkspace, error) {

	// Go make the request to the Postman API
	responseBody, statusCode, err := pc.getPostmanResponseBodyBytes(ctx, fmt.Sprintf("%s/workspaces/%s", POSTMAN_API_BASE_URL, id))
	if err != nil {
		return PostmanWorkspace{}, fmt.Errorf("could not get postman workspace with id %s: %w", id, err)
	}

	switch statusCode {
	case 200:
		// Go ahead and parse the response
		workspaceResponse := PostmanApiResponse_GetWorkspaceResponse_200{}
		if err := json.Unmarshal(responseBody, &workspaceResponse); err != nil {
			// TODO: Add ids to the error messages
			return PostmanWorkspace{}, fmt.Errorf("could not parse postman workpsace %d response: %w", statusCode, err)
		}

		return PostmanWorkspace{
			Id:        workspaceResponse.Workspace.Id,
			Name:      workspaceResponse.Workspace.Name,
			CreatedBy: workspaceResponse.Workspace.CreatedBy,
			EnvironmentSummaries: fp.Map(func(s struct{ Id, Name, Uid string }) PostmanEnvironmentSummary {
				return PostmanEnvironmentSummary{Id: s.Id, Name: s.Name, Uid: s.Uid}
			})([]struct{ Id, Name, Uid string }(workspaceResponse.Workspace.Environments)),
			CollectionSummaries: fp.Map(func(s struct{ Id, Name, Uid string }) PostmanCollectionSummary {
				return PostmanCollectionSummary{Id: s.Id, Name: s.Name, Uid: s.Uid}
			})([]struct{ Id, Name, Uid string }(workspaceResponse.Workspace.Collections)),
		}, nil
	case 401:
		workspaceResponse := PostmanApiResponse_GetWorkspaceResponse_401{}
		if err := json.Unmarshal(responseBody, &workspaceResponse); err != nil {
			return PostmanWorkspace{}, fmt.Errorf("could not parse postman workspace %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 401 from the postman workspace api",
			"postman_error_name", workspaceResponse.Error.Name,
			"postman_error_message", workspaceResponse.Error.Message)

		return PostmanWorkspace{}, fmt.Errorf("postman workspace api returned a 401 - do we have the right access?")
	case 403:
		workspaceResponse := PostmanApiResponse_GetWorkspaceResponse_403{}
		if err := json.Unmarshal(responseBody, &workspaceResponse); err != nil {
			return PostmanWorkspace{}, fmt.Errorf("could not parse postman workspace %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 403 from the postman workspace api",
			"postman_error_name", workspaceResponse.Error.Name,
			"postman_error_message", workspaceResponse.Error.Message)

		return PostmanWorkspace{}, fmt.Errorf("postman workspace api returned a 403 - do we have the right access?")
	case 404:
		workspaceResponse := PostmanApiResponse_GetWorkspaceResponse_404{}
		if err := json.Unmarshal(responseBody, &workspaceResponse); err != nil {
			return PostmanWorkspace{}, fmt.Errorf("could not parse postman workspace %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 404 from the postman workspace api",
			"postman_error_name", workspaceResponse.Error.Name,
			"postman_error_message", workspaceResponse.Error.Message)

		return PostmanWorkspace{}, fmt.Errorf("postman workspace api returned a 404")
	case 429:
		workspaceResponse := PostmanApiResponse_GetWorkspaceResponse_429{}
		if err := json.Unmarshal(responseBody, &workspaceResponse); err != nil {
			return PostmanWorkspace{}, fmt.Errorf("could not parse postman workspace %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 429 from the postman workspace api",
			"postman_error", workspaceResponse.Error,
			"postman_error_message", workspaceResponse.Message)

		return PostmanWorkspace{}, fmt.Errorf("postman workspace api returned a 429 - are too many scanners running against the postman api?")
	default:
		return PostmanWorkspace{}, fmt.Errorf("postman workspace endpoint returned unexpected status code: %d", statusCode)
	}
}

func (pc *postmanApiClient) GetCollectionByUid(ctx context.Context, uid string) (PostmanCollection, error) {

	// Go make the request to the Postman API
	responseBody, statusCode, err := pc.getPostmanResponseBodyBytes(ctx, fmt.Sprintf("%s/collections/%s", POSTMAN_API_BASE_URL, uid))
	if err != nil {
		return PostmanCollection{}, fmt.Errorf("could not get postman collection: %w", err)
	}

	switch statusCode {
	case 200:
		// Go ahead and parse the response
		collectionResponse := PostmanApiResponse_GetCollectionResponse_200{}
		if err := json.Unmarshal(responseBody, &collectionResponse); err != nil {
			return PostmanCollection{}, fmt.Errorf("could not parse postman collection %d response: %w", statusCode, err)
		}
		return PostmanCollection{
			Uid: collectionResponse.Collection.Info.Uid,
		}, nil
	case 401:
		collectionResponse := PostmanApiResponse_GetCollectionResponse_401{}
		if err := json.Unmarshal(responseBody, &collectionResponse); err != nil {
			return PostmanCollection{}, fmt.Errorf("could not parse postman collection %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 401 from the postman collection api",
			"postman_error_name", collectionResponse.Error.Name,
			"postman_error_message", collectionResponse.Error.Message)

		return PostmanCollection{}, fmt.Errorf("postman collection api returned a 401 - do we have the right access?")
	case 404:
		collectionResponse := PostmanApiResponse_GetCollectionResponse_404{}
		if err := json.Unmarshal(responseBody, &collectionResponse); err != nil {
			return PostmanCollection{}, fmt.Errorf("could not parse postman collection %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 404 from the postman collection api",
			"postman_error_name", collectionResponse.Error.Name,
			"postman_error_message", collectionResponse.Error.Message)

		return PostmanCollection{}, fmt.Errorf("postman collection api returned a 404")
	case 429:
		collectionResponse := PostmanApiResponse_GetCollectionResponse_429{}
		if err := json.Unmarshal(responseBody, &collectionResponse); err != nil {
			return PostmanCollection{}, fmt.Errorf("could not parse postman collection %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 429 from the postman collection api",
			"postman_error", collectionResponse.Error,
			"postman_error_message", collectionResponse.Message)

		return PostmanCollection{}, fmt.Errorf("postman collection api returned a 429 - are too many scanners running against the postman api?")
	default:
		return PostmanCollection{}, fmt.Errorf("postman collection endpoint returned unexpected status code: %d", statusCode)
	}
}

func (pc *postmanApiClient) GetEnvironmentByUid(ctx context.Context, uid string) (PostmanEnvironment, error) {

	// Go make the request to the Postman API
	responseBody, statusCode, err := pc.getPostmanResponseBodyBytes(ctx, fmt.Sprintf("https://api.getpostman.com/environments/%s", uid))
	if err != nil {
		return PostmanEnvironment{}, fmt.Errorf("could not get postman collection: %w", err)
	}

	switch statusCode {
	case 200:
		// Go ahead and parse the response
		environmentResponse := PostmanApiResponse_GetEnvironmentResponse_200{}
		if err := json.Unmarshal(responseBody, &environmentResponse); err != nil {
			return PostmanEnvironment{}, fmt.Errorf("could not parse postman environment %d response: %w", statusCode, err)
		}
		return PostmanEnvironment{
			Uid: fmt.Sprintf("%s-%s", environmentResponse.Environment.Owner, environmentResponse.Environment.Id),
			Id:  environmentResponse.Environment.Id,
		}, nil
	case 401:
		environmentResponse := PostmanApiResponse_GetEnvironmentResponse_401{}
		if err := json.Unmarshal(responseBody, &environmentResponse); err != nil {
			return PostmanEnvironment{}, fmt.Errorf("could not parse postman environment %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 401 from the postman environment api",
			"postman_error_name", environmentResponse.Error.Name,
			"postman_error_message", environmentResponse.Error.Message)

		return PostmanEnvironment{}, fmt.Errorf("postman environment api returned a 401 - do we have the right access?")
	case 404:
		environmentResponse := PostmanApiResponse_GetEnvironmentResponse_404{}
		if err := json.Unmarshal(responseBody, &environmentResponse); err != nil {
			return PostmanEnvironment{}, fmt.Errorf("could not parse postman environment %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 404 from the postman environment api",
			"postman_error_name", environmentResponse.Error.Name,
			"postman_error_message", environmentResponse.Error.Message)

		return PostmanEnvironment{}, fmt.Errorf("postman environment api returned a 404")
	case 429:
		environmentResponse := PostmanApiResponse_GetEnvironmentResponse_429{}
		if err := json.Unmarshal(responseBody, &environmentResponse); err != nil {
			return PostmanEnvironment{}, fmt.Errorf("could not parse postman environment %d response: %w", statusCode, err)
		}

		// Give ourselves some nice logging information
		ctx.Logger().V(2).Info(
			"got a 429 from the postman environment api",
			"postman_error", environmentResponse.Error,
			"postman_error_message", environmentResponse.Message)

		return PostmanEnvironment{}, fmt.Errorf("postman environment api returned a 429 - are too many scanners running against the postman api?")
	default:
		return PostmanEnvironment{}, fmt.Errorf("postman environment endpoint returned unexpected status code: %d", statusCode)
	}
}
