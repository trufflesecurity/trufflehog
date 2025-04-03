package postman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"golang.org/x/time/rate"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

const (
	WORKSPACE_URL      = "https://api.getpostman.com/workspaces/%s"
	ENVIRONMENTS_URL   = "https://api.getpostman.com/environments/%s"
	COLLECTIONS_URL    = "https://api.getpostman.com/collections/%s"
	userAgent          = "PostmanRuntime/7.26.8"
	defaultContentType = "*"
)

type Workspace struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Type            string       `json:"type"`
	Description     string       `json:"description"`
	Visibility      string       `json:"visibility"`
	CreatedBy       string       `json:"createdBy"`
	UpdatedBy       string       `json:"updatedBy"`
	CreatedAt       string       `json:"createdAt"`
	UpdatedAt       string       `json:"updatedAt"`
	Collections     []IDNameUUID `json:"collections"`
	Environments    []IDNameUUID `json:"environments"`
	CollectionsRaw  []Collection
	EnvironmentsRaw []VariableData
}

type IDNameUUID struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uid"`
}

type KeyValue struct {
	Key          string `json:"key"`
	Value        any    `json:"value"`
	Enabled      bool   `json:"enabled,omitempty"`
	Type         string `json:"type,omitempty"`
	SessionValue string `json:"sessionValue,omitempty"`
	Id           string `json:"id,omitempty"`
}

type VariableData struct {
	ID        string     `json:"id"` // For globals and envs, this is just the UUID, not the full ID.
	Name      string     `json:"name"`
	KeyValues []KeyValue `json:"values"`
	Owner     string     `json:"owner"`
	IsPublic  bool       `json:"isPublic"`
	CreatedAt string     `json:"createdAt"`
	UpdatedAt string     `json:"updatedAt"`
}

type Environment struct {
	VariableData `json:"environment"`
}

type Metadata struct {
	WorkspaceUUID   string
	WorkspaceName   string
	CreatedBy       string
	EnvironmentID   string
	CollectionInfo  Info
	FolderID        string // UUID of the folder (but not full ID)
	FolderName      string // Folder path if the item is nested under one or more folders
	RequestID       string // UUID of the request (but not full ID)
	RequestName     string
	FullID          string //full ID of the reference item (created_by + ID) OR just the UUID
	Link            string //direct link to the folder (could be .json file path)
	Type            string //folder, request, etc.
	EnvironmentName string
	FieldType       string // Path of the item type
	fromLocal       bool
	LocationType    source_metadatapb.PostmanLocationType // The distinct Postman location type that the item falls under
}

type Collection struct {
	Info      Info       `json:"info"`
	Items     []Item     `json:"item,omitempty"`
	Auth      Auth       `json:"auth,omitempty"`
	Events    []Event    `json:"event,omitempty"`
	Variables []KeyValue `json:"variable,omitempty"`
}

type Info struct {
	PostmanID   string    `json:"_postman_id"` // This is a UUID. Needs createdBy ID prefix to be used with API.
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Schema      string    `json:"schema"`
	UpdatedAt   time.Time `json:"updatedAt"`
	UID         string    `json:"uid"` //Need to use this to get the collection via API
}

type Item struct {
	Name        string     `json:"name"`
	Items       []Item     `json:"item,omitempty"`
	ID          string     `json:"id,omitempty"`
	Auth        Auth       `json:"auth,omitempty"`
	Events      []Event    `json:"event,omitempty"`
	Variable    []KeyValue `json:"variable,omitempty"`
	Request     Request    `json:"request,omitempty"`
	Response    []Response `json:"response,omitempty"`
	Description string     `json:"description,omitempty"`
	UID         string     `json:"uid,omitempty"` //Need to use this to get the collection via API. The UID is a concatenation of the ID and the user ID of whoever created the item.
}

type Auth struct {
	Type   string     `json:"type"`
	Apikey []KeyValue `json:"apikey,omitempty"`
	Bearer []KeyValue `json:"bearer,omitempty"`
	AWSv4  []KeyValue `json:"awsv4,omitempty"`
	Basic  []KeyValue `json:"basic,omitempty"`
	OAuth2 []KeyValue `json:"oauth2,omitempty"`
}

type Event struct {
	Listen string `json:"listen"`
	Script Script `json:"script"`
}

type Script struct {
	Type string   `json:"type"`
	Exec []string `json:"exec"`
	Id   string   `json:"id"`
}

type Request struct {
	Auth           Auth            `json:"auth,omitempty"`
	Method         string          `json:"method"`
	HeaderRaw      json.RawMessage `json:"header,omitempty"`
	HeaderKeyValue []KeyValue
	HeaderString   []string
	Body           Body   `json:"body,omitempty"` //Need to update with additional options
	URL            URL    `json:"url"`
	Description    string `json:"description,omitempty"`
}

type Body struct {
	Mode       string      `json:"mode"`
	Raw        string      `json:"raw,omitempty"`
	File       BodyFile    `json:"file,omitempty"`
	URLEncoded []KeyValue  `json:"urlencoded,omitempty"` //FINISH
	FormData   []KeyValue  `json:"formdata,omitempty"`   //FINISH
	GraphQL    BodyGraphQL `json:"graphql,omitempty"`
}

type BodyGraphQL struct {
	Query     string `json:"query"`
	Variables string `json:"variables"`
}

type BodyFile struct {
	Src string `json:"src"`
}

type URL struct {
	Raw      string     `json:"raw"`
	Protocol string     `json:"protocol"`
	Host     []string   `json:"host"`
	Path     []string   `json:"path"`
	Query    []KeyValue `json:"query,omitempty"`
}

type Response struct {
	ID              string          `json:"id"`
	Name            string          `json:"name,omitempty"`
	OriginalRequest Request         `json:"originalRequest,omitempty"`
	HeaderRaw       json.RawMessage `json:"header,omitempty"`
	HeaderKeyValue  []KeyValue
	HeaderString    []string
	Body            string `json:"body,omitempty"`
	UID             string `json:"uid,omitempty"`
}

// A Client manages communication with the Postman API.
type Client struct {
	// HTTP client used to communicate with the API
	HTTPClient *http.Client

	// Headers to attach to every requests made with the client.
	Headers map[string]string

	// Rate limiter needed for Postman API workspace and collection requests. Postman API rate limit
	// is 10 calls in 10 seconds for GET /collections, GET /workspaces, and GET /workspaces/{id} endpoints.
	WorkspaceAndCollectionRateLimiter *rate.Limiter

	// Rate limiter needed for Postman API. General rate limit is 300 requests per minute.
	GeneralRateLimiter *rate.Limiter
}

// NewClient returns a new Postman API client.
func NewClient(postmanToken string) *Client {
	bh := map[string]string{
		"Content-Type": defaultContentType,
		"User-Agent":   userAgent,
		"X-API-Key":    postmanToken,
	}

	c := &Client{
		HTTPClient:                        http.DefaultClient,
		Headers:                           bh,
		WorkspaceAndCollectionRateLimiter: rate.NewLimiter(rate.Every(time.Second), 1),
		GeneralRateLimiter:                rate.NewLimiter(rate.Every(time.Second/5), 1),
	}

	return c
}

// NewRequest creates an API request (Only GET needed for our interaction w/ Postman)
// If specified, the map provided by headers will be used to update request headers.
func (c *Client) NewRequest(urlStr string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	var h = c.Headers
	for k, v := range headers {
		h[k] = v
	}

	for k, v := range h {
		req.Header.Set(k, v)
	}

	return req, nil
}

// checkResponseStatus checks the API response for errors and returns them if present.
// A Response is considered an error if it has a status code outside the 2XX range.
func checkResponseStatus(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	return fmt.Errorf("postman Request failed with status code: %d", r.StatusCode)
}

func (c *Client) getPostmanReq(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	req, err := c.NewRequest(url, headers)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	ctx.Logger().V(4).Info("Postman API reponse headers are available", "response_header", resp.Header)

	if err := checkResponseStatus(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// EnumerateWorkspaces returns the workspaces for a given user (both private, public, team and personal).
// Consider adding additional flags to support filtering.
func (c *Client) EnumerateWorkspaces(ctx context.Context) ([]Workspace, error) {
	ctx.Logger().V(2).Info("enumerating workspaces")
	workspacesObj := struct {
		Workspaces []Workspace `json:"workspaces"`
	}{}

	if err := c.WorkspaceAndCollectionRateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("could not wait for rate limiter during workspaces enumeration getting: %w", err)
	}
	r, err := c.getPostmanReq(ctx, "https://api.getpostman.com/workspaces", nil)
	if err != nil {
		return nil, fmt.Errorf("could not get workspaces during enumeration: %w", err)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body for workspaces during enumeration: %w", err)
	}
	r.Body.Close()

	if err := json.Unmarshal([]byte(body), &workspacesObj); err != nil {
		return nil, fmt.Errorf("could not unmarshal workspaces JSON during enumeration: %w", err)
	}

	for i, workspace := range workspacesObj.Workspaces {
		tempWorkspace, err := c.GetWorkspace(ctx, workspace.ID)
		if err != nil {
			return nil, fmt.Errorf("could not get workspace %q (%s) during enumeration: %w", workspace.Name, workspace.ID, err)
		}
		workspacesObj.Workspaces[i] = tempWorkspace

		ctx.Logger().V(3).Info("individual workspace getting added to the slice", "workspace", workspacesObj.Workspaces[i])
	}

	return workspacesObj.Workspaces, nil
}

// GetWorkspace returns the workspace for a given workspace
func (c *Client) GetWorkspace(ctx context.Context, workspaceUUID string) (Workspace, error) {
	ctx.Logger().V(2).Info("getting workspace", "workspace", workspaceUUID)
	obj := struct {
		Workspace Workspace `json:"workspace"`
	}{}

	url := fmt.Sprintf(WORKSPACE_URL, workspaceUUID)
	if err := c.WorkspaceAndCollectionRateLimiter.Wait(ctx); err != nil {
		return Workspace{}, fmt.Errorf("could not wait for rate limiter during workspace getting: %w", err)
	}
	r, err := c.getPostmanReq(ctx, url, nil)
	if err != nil {
		return Workspace{}, fmt.Errorf("could not get workspace (%s): %w", workspaceUUID, err)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return Workspace{}, fmt.Errorf("could not read response body for workspace (%s): %w", workspaceUUID, err)
	}
	r.Body.Close()

	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return Workspace{}, fmt.Errorf("could not unmarshal workspace JSON for workspace (%s): %w", workspaceUUID, err)
	}

	return obj.Workspace, nil
}

// GetEnvironmentVariables returns the environment variables for a given environment
func (c *Client) GetEnvironmentVariables(ctx context.Context, environment_uuid string) (VariableData, error) {
	obj := struct {
		VariableData VariableData `json:"environment"`
	}{}

	url := fmt.Sprintf(ENVIRONMENTS_URL, environment_uuid)
	if err := c.GeneralRateLimiter.Wait(ctx); err != nil {
		return VariableData{}, fmt.Errorf("could not wait for rate limiter during environment variable getting: %w", err)
	}
	r, err := c.getPostmanReq(ctx, url, nil)
	if err != nil {
		return VariableData{}, fmt.Errorf("could not get env variables for environment (%s): %w", environment_uuid, err)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return VariableData{}, fmt.Errorf("could not read env var response body for environment (%s): %w", environment_uuid, err)
	}
	r.Body.Close()
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return VariableData{}, fmt.Errorf("could not unmarshal env variables JSON for environment (%s): %w", environment_uuid, err)
	}

	return obj.VariableData, nil
}

// GetCollection returns the collection for a given collection
func (c *Client) GetCollection(ctx context.Context, collection_uuid string) (Collection, error) {
	obj := struct {
		Collection Collection `json:"collection"`
	}{}

	url := fmt.Sprintf(COLLECTIONS_URL, collection_uuid)
	if err := c.WorkspaceAndCollectionRateLimiter.Wait(ctx); err != nil {
		return Collection{}, fmt.Errorf("could not wait for rate limiter during collection getting: %w", err)
	}
	r, err := c.getPostmanReq(ctx, url, nil)
	if err != nil {
		return Collection{}, fmt.Errorf("could not get collection (%s): %w", collection_uuid, err)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return Collection{}, fmt.Errorf("could not read response body for collection (%s): %w", collection_uuid, err)
	}
	r.Body.Close()
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return Collection{}, fmt.Errorf("could not unmarshal JSON for collection (%s): %w", collection_uuid, err)
	}

	// Loop used to deal with seeing whether a request/response header is a string or a key value pair
	for i := range obj.Collection.Items {
		if obj.Collection.Items[i].Request.HeaderRaw != nil {
			if err := json.Unmarshal(obj.Collection.Items[i].Request.HeaderRaw, &obj.Collection.Items[i].Request.HeaderKeyValue); err == nil {
			} else if err := json.Unmarshal(obj.Collection.Items[i].Request.HeaderRaw, &obj.Collection.Items[i].Request.HeaderString); err == nil {
			} else {
				return Collection{}, fmt.Errorf("could not unmarshal request header JSON for collection (%s): %w", collection_uuid, err)
			}
		}

		for j := range obj.Collection.Items[i].Response {
			if err := json.Unmarshal(obj.Collection.Items[i].Response[j].OriginalRequest.HeaderRaw, &obj.Collection.Items[i].Response[j].OriginalRequest.HeaderKeyValue); err == nil {
			} else if err := json.Unmarshal(obj.Collection.Items[i].Response[j].OriginalRequest.HeaderRaw, &obj.Collection.Items[i].Response[j].OriginalRequest.HeaderString); err == nil {
			} else {
				return Collection{}, fmt.Errorf("could not unmarshal original request header in response JSON for collection (%s): %w", collection_uuid, err)
			}

			if err := json.Unmarshal(obj.Collection.Items[i].Response[j].HeaderRaw, &obj.Collection.Items[i].Response[j].HeaderKeyValue); err == nil {
			} else if err := json.Unmarshal(obj.Collection.Items[i].Response[j].HeaderRaw, &obj.Collection.Items[i].Response[j].HeaderString); err == nil {
			} else {
				return Collection{}, fmt.Errorf("could not unmarshal response header JSON for collection (%s): %w", collection_uuid, err)
			}
		}
	}

	return obj.Collection, nil
}
