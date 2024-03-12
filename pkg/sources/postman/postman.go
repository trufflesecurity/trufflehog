package postman

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	SourceType       = sourcespb.SourceType_SOURCE_TYPE_POSTMAN
	LINK_BASE_URL    = "https://go.postman.co/"
	GLOBAL_TYPE      = "globals"
	ENVIRONMENT_TYPE = "environment"
	AUTH_TYPE        = "authorization"
	REQUEST_TYPE     = "request"
	FOLDER_TYPE      = "folder"
	COLLECTION_TYPE  = "collection"
	EVENT_TYPE       = "script"
)

type Source struct {
	name             string
	sourceId         sources.SourceID
	jobId            sources.JobID
	verify           bool
	log              logr.Logger
	jobPool          *errgroup.Group
	client           *Client
	conn             *sourcespb.Postman
	detectorKeywords map[string]struct{}

	// Keywords are words that are discovered when we walk through postman data.
	// These keywords are then injected into data that is sent to the detectors.
	keywords []string
	sub      *Substitution

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init returns an initialized Postman source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)
	s.detectorKeywords = make(map[string]struct{})
	s.sub = NewSubstitution()

	s.log = ctx.Logger()

	var conn sourcespb.Postman
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.conn = &conn

	for _, key := range s.conn.DetectorKeywords {
		s.detectorKeywords[key] = struct{}{}
	}

	switch conn.Credential.(type) {
	case *sourcespb.Postman_Token:
		if conn.GetToken() == "" {
			return errors.New("Postman token is empty")
		}
		s.client = NewClient(conn.GetToken())
		s.client.HTTPClient = common.RetryableHttpClientTimeout(3)
	case *sourcespb.Postman_Unauthenticated:
		s.client = nil
		// No client needed if reading from local
	default:
		return errors.New("credential type not implemented for Postman")
	}

	return nil
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	// Scan workspaces
	for _, workspaceID := range s.conn.Workspaces {
		w, err := s.client.GetWorkspace(workspaceID)
		if err != nil {
			s.log.Error(err, "could not get workspace object", "workspace_uuid", workspaceID)
		}
		s.scanWorkspace(ctx, chunksChan, w)
	}

	// Scan collections
	for _, collectionID := range s.conn.Collections {
		collection, err := s.client.GetCollection(collectionID)
		if err != nil {
			s.log.Error(err, "could not get collection object", "collection_uuid", collectionID)
		}
		s.scanCollection(ctx, chunksChan, Metadata{}, collection)
	}

	// Scan personal workspaces (from API token)
	if s.conn.Workspaces == nil && s.conn.Collections == nil && s.conn.Environments == nil {
		workspaces, err := s.client.EnumerateWorkspaces()
		if err != nil {
			ctx.Logger().Error(errors.New("Could not enumerate any workspaces for the API token provided"), "failed to scan postman")
			return nil
		}
		for _, workspace := range workspaces {
			s.scanWorkspace(ctx, chunksChan, workspace)
		}
	}

	return nil
}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspace Workspace) {
	// reset keywords for each workspace
	s.keywords = []string{workspace.Name}

	// initiate metadata to track the tree structure of postman data
	metadata := Metadata{
		WorkspaceUUID: workspace.ID,
		WorkspaceName: workspace.Name,
		CreatedBy:     workspace.CreatedBy,
		Type:          "workspace",
	}

	// scan global variables
	ctx.Logger().V(2).Info("starting scanning global variables")
	globalVars, err := s.client.GetGlobalVariables(workspace.ID)
	if err != nil {
		s.log.Error(err, "could not get global variables object")
	}

	metadata.Type = GLOBAL_TYPE
	metadata.Link = LINK_BASE_URL + "workspace/" + workspace.ID + "/" + GLOBAL_TYPE
	metadata.FullID = workspace.CreatedBy + "-" + globalVars.ID

	s.scanVariableData(ctx, chunksChan, metadata, globalVars)
	ctx.Logger().V(2).Info("finished scanning global variables")

	// gather and scan environment variables
	for _, envID := range workspace.Environments {
		envVars, err := s.client.GetEnvironmentVariables(envID.UUID)
		if err != nil {
			s.log.Error(err, "could not get environment object", "environment_uuid", envID.UUID)
		}
		// s.scanEnvironment(ctx, chunksChan, env, workspace)
		metadata.Type = ENVIRONMENT_TYPE
		metadata.Link = LINK_BASE_URL + ENVIRONMENT_TYPE + "/" + envVars.ID
		metadata.FullID = envVars.ID
		metadata.EnvironmentID = envID.UUID

		ctx.Logger().V(2).Info("scanning environment vars", "environment_uuid", metadata.FullID)
		for _, word := range strings.Split(envVars.Name, " ") {
			s.keywords = append(s.keywords, string(word))
		}

		s.scanVariableData(ctx, chunksChan, metadata, envVars)
		ctx.Logger().V(2).Info("finished scanning environment vars", "environment_uuid", metadata.FullID)
	}
	ctx.Logger().V(2).Info("finished scanning environments")

	// scan all the collections in the workspace.
	// at this point we have all the possible
	// substitutions from Global and Environment variables
	for _, collectionID := range workspace.Collections {
		collection, err := s.client.GetCollection(collectionID.UUID)
		if err != nil {
			s.log.Error(err, "could not get collection object", "collection_uuid", collectionID.UUID)
		}
		s.scanCollection(ctx, chunksChan, metadata, collection)
	}
}

// scanCollection scans a collection and all its items, folders, and requests.
// locally scoped Metadata is updated as we drill down into the collection.
func (s *Source) scanCollection(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, collection Collection) {
	ctx.Logger().V(2).Info("starting scanning collection", collection.Info.Name, "uuid", collection.Info.UID)
	metadata.CollectionInfo = collection.Info
	metadata.Type = COLLECTION_TYPE

	if metadata.CollectionInfo.UID != "" {
		// means we're reading in from an API call vs. local JSON file read
		metadata.FullID = metadata.CollectionInfo.UID
		metadata.Link = LINK_BASE_URL + COLLECTION_TYPE + "/" + metadata.FullID
	} else {
		// means we're reading in from a local JSON file
		metadata.FullID = metadata.CollectionInfo.PostmanID
		metadata.Link = "../" + metadata.FullID + ".json"
	}

	// variables must be scanned first before drilling down into the folders and events
	// because we need to pick up the substitutions from the top level collection variables
	s.scanVariableData(ctx, chunksChan, metadata, VariableData{
		KeyValues: collection.Variables,
	})

	for _, event := range collection.Events {
		s.scanEvent(ctx, chunksChan, metadata, event)
	}

	for _, item := range collection.Items {
		s.scanItem(ctx, chunksChan, collection, metadata, item)
	}

}

// ZRNOTE: rename back to folder and change struct name from Item to Folder
func (s *Source) scanItem(ctx context.Context, chunksChan chan *sources.Chunk, collection Collection, metadata Metadata, item Item) {
	s.keywords = append(s.keywords, item.Name)

	// override the base collection metadata with item-specific metadata
	metadata.FolderID = item.ID
	metadata.Type = FOLDER_TYPE
	if metadata.FolderName != "" {
		// keep track of the folder hierarchy
		metadata.FolderName = metadata.FolderName + " > " + item.Name
	} else {
		metadata.FolderName = item.Name
	}

	if item.UID != "" {
		metadata.FullID = item.UID
		metadata.Link = LINK_BASE_URL + FOLDER_TYPE + "/" + metadata.FullID
	} else {
		metadata.FullID = item.ID
		metadata.Link = "../" + collection.metadata.FullID + ".json"
	}

	// recurse through the folders
	for _, subItem := range item.Items {
		s.scanItem(ctx, chunksChan, collection, metadata, subItem)
	}

	// check if there are any requests in the folder
	if item.Request.Method != "" {
		metadata.RequestID = item.ID
		metadata.RequestName = item.Name
		metadata.Type = REQUEST_TYPE
		if item.UID != "" {
			// Route to API endpoint
			metadata.FullID = item.UID
			metadata.Link = LINK_BASE_URL + REQUEST_TYPE + "/" + item.UID
		} else {
			// Route to collection.json
			metadata.FullID = item.ID
			metadata.Link = "../" + metadata.CollectionInfo.PostmanID + ".json"
		}
		s.scanHTTPRequest(ctx, chunksChan, metadata, item.Request)
	}

	// check if there are any responses in the folder
	for _, response := range item.Response {
		s.scanHTTPResponse(ctx, chunksChan, metadata, response)
	}

	for _, event := range item.Events {
		s.scanEvent(ctx, chunksChan, metadata, event)
	}

	// an auth all by its lonesome could be inherited to subfolders and requests
	s.scanAuth(ctx, chunksChan, metadata, item.Auth, item.Request.URL)
}

func (s *Source) scanEvent(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, event Event) {
	metadata.Type = metadata.Type + " > event"
	data := strings.Join(event.Script.Exec, " ")

	// Prep direct links
	metadata.Link = LINK_BASE_URL + metadata.Type + "/" + metadata.FullID
	if event.Listen == "prerequest" {
		metadata.Link += "?tab=pre-request-scripts"
	} else {
		metadata.Link += "?tab=tests"
	}

	s.scanData(ctx, chunksChan, strings.Join(s.buildSubstitueSet(metadata, data), ""), metadata)
}

func (s *Source) scanAuth(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, auth Auth, u URL) string {
	var authData string
	switch auth.Type {
	case "apikey":
		var apiKeyValue, apiKeyName string
		for _, kv := range auth.Apikey {
			switch kv.Key {
			case "key":
				apiKeyValue = fmt.Sprintf("%v", kv.Value)
			case "value":
				apiKeyName = fmt.Sprintf("%v", kv.Value)
			}
		}
		authData += fmt.Sprintf("%s=%s\n", apiKeyName, apiKeyValue)
	case "awsSigV4", "awsv4":
		for _, kv := range auth.AWSv4 {
			switch kv.Key {
			case "accessKey":
				authData += fmt.Sprintf("accessKey:%s ", kv.Value)
			case "secretKey":
				authData += fmt.Sprintf("secretKey:%s ", kv.Value)
			case "region":
				authData += fmt.Sprintf("region:%s ", kv.Value)
			case "service":
				authData += fmt.Sprintf("service:%s ", kv.Value)
			}
		}
	case "bearer":
		var bearerKey, bearerValue string
		for _, kv := range auth.Bearer {
			bearerValue = fmt.Sprintf("%v", kv.Value)
			bearerKey = fmt.Sprintf("%v", kv.Key)
		}
		authData += fmt.Sprintf("%s:%s\n", bearerKey, bearerValue)
	case "basic":
		username := ""
		password := ""

		for _, kv := range auth.Basic {
			switch kv.Key {
			case "username":
				username = fmt.Sprintf("%v", kv.Value)
			case "password":
				password = fmt.Sprintf("%v", kv.Value)
			}
		}
		if u.Raw != "" {
			parsedURL, err := url.Parse(u.Raw)
			if err != nil {
				ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
				return ""
			}

			parsedURL.User = url.User(username + ":" + password)
			decodedURL, err := url.PathUnescape(parsedURL.String())
			if err != nil {
				ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
				return ""
			}
			authData += decodedURL
		}
	case "oauth2":
		for _, oauth := range auth.OAuth2 {
			switch oauth.Key {
			case "accessToken", "refreshToken", "clientId", "clientSecret", "accessTokenUrl", "authUrl":
				authData += fmt.Sprintf("%s:%v ", oauth.Key, oauth.Value)
			}
		}
	case "noauth":
		return ""
	default:
		return ""
	}

	m.Link = m.Link + "?tab=authorization"
	m.Type = m.Type + " > authorization"
	m.FieldType = AUTH_TYPE
	s.scanData(ctx, chunksChan, strings.Join(s.buildSubstitueSet(m, authData), ""), m)

	return ""
}

func (s *Source) scanHTTPRequest(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, r Request) {
	s.keywords = append(s.keywords, r.URL.Host...)

	// Add in var procesisng for headers
	if r.Header != nil {
		vars := VariableData{
			KeyValues: r.Header,
		}
		metadata.Type = metadata.Type + " > header"
		s.scanVariableData(ctx, chunksChan, metadata, vars)
	}

	if r.URL.Raw != "" {
		metadata.Type = metadata.Type + " > request URL"
		s.scanData(ctx, chunksChan, strings.Join(s.buildSubstitueSet(metadata, r.URL.Raw), ""), metadata)
	}

	if len(r.URL.Query) > 0 {
		vars := VariableData{
			KeyValues: r.URL.Query,
		}
		metadata.Type = metadata.Type + " > GET parameters (query)"
		s.scanVariableData(ctx, chunksChan, metadata, vars)
	}

	if r.Auth.Type != "" {
		metadata.Type = metadata.Type + " > request auth"
		s.scanAuth(ctx, chunksChan, metadata, r.Auth, r.URL)
	}

	if r.Body.Mode != "" {
		metadata.Type = metadata.Type + " > body"
		s.scanBody(ctx, chunksChan, metadata, r.Body)
	}
}

func (s *Source) scanBody(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, b Body) {
	m.Link = m.Link + "?tab=body"
	switch b.Mode {
	case "formdata":
		m.Type = m.Type + " > form data"
		vars := VariableData{
			KeyValues: b.FormData,
		}
		s.scanVariableData(ctx, chunksChan, m, vars)
	case "urlencoded":
		m.Type = m.Type + " > url encoded"
		vars := VariableData{
			KeyValues: b.URLEncoded,
		}
		s.scanVariableData(ctx, chunksChan, m, vars)
	case "raw", "graphql":
		data := b.Raw
		if b.Mode == "graphql" {
			m.Type = m.Type + " > graphql"
			data = b.GraphQL.Query + " " + b.GraphQL.Variables
		}
		if b.Mode == "raw" {
			m.Type = m.Type + " > raw"
		}
		s.scanData(ctx, chunksChan, strings.Join(s.buildSubstitueSet(m, data), ""), m)
	default:
		break
	}
}

func (s *Source) scanHTTPResponse(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, response Response) {
	if response.UID != "" {
		m.Link = LINK_BASE_URL + "example/" + response.UID
		m.FullID = response.UID
	}

	if response.Header != nil {
		vars := VariableData{
			KeyValues: response.Header,
		}
		m.Type = m.Type + " > response header"
		s.scanVariableData(ctx, chunksChan, m, vars)
	}

	// Body in a response is just a string
	if response.Body != "" {
		m.Type = m.Type + " > response body"
		s.scanData(ctx, chunksChan, strings.Join(s.buildSubstitueSet(m, response.Body), ""), m)
	}

	if response.OriginalRequest.Method != "" {
		m.Type = m.Type + " > original request"
		s.scanHTTPRequest(ctx, chunksChan, m, response.OriginalRequest)
	}
}

func (s *Source) scanVariableData(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, variableData VariableData) {
	if len(variableData.KeyValues) == 0 {
		ctx.Logger().V(2).Info("no variables to scan", "type", m.Type, "uuid", m.FullID)
		return
	}

	// If collection and not a JSON file, then append the tab=variables to the link
	if m.Type == COLLECTION_TYPE {
		if !strings.HasSuffix(m.Link, ".json") {
			m.Link += "?tab=variables"
		}
	}

	values := []string{}
	for _, kv := range variableData.KeyValues {
		s.keywords = append(s.keywords, kv.Key)
		valStr := fmt.Sprintf("%v", kv.Value)
		if valStr != "" {
			s.sub.add(m, kv.Key, valStr)
		} else if kv.SessionValue != "" {
			valStr = fmt.Sprintf("%v", kv.SessionValue)
		}
		if valStr == "" {
			continue
		}
		values = append(values, s.buildSubstitueSet(m, valStr)...)
	}

	m.FieldType = m.Type + " variables"
	s.scanData(ctx, chunksChan, strings.Join(values, ""), m)
}

func (s *Source) scanData(ctx context.Context, chunksChan chan *sources.Chunk, data string, metadata Metadata) {
	if data == "" {
		return
	}
	fmt.Println("Scanning data: ")
	fmt.Println(data)

	chunksChan <- &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		Data:       []byte(data),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Postman{
				Postman: &source_metadatapb.Postman{
					Link:            metadata.Link,
					WorkspaceUuid:   metadata.WorkspaceUUID,
					WorkspaceName:   metadata.WorkspaceName,
					CollectionId:    metadata.CollectionInfo.PostmanID,
					CollectionName:  metadata.CollectionInfo.Name,
					EnvironmentId:   metadata.EnvironmentID,
					EnvironmentName: metadata.EnvironmentName,
					RequestId:       metadata.RequestID,
					RequestName:     metadata.RequestName,
					FolderId:        metadata.FolderID,
					FolderName:      metadata.FolderName,
					FieldType:       metadata.FieldType,
					FieldName:       metadata.FieldName,
					VariableType:    metadata.VarType,
				},
			},
		},
		Verify: s.verify,
	}
}

func filterKeywords(keys []string, detectorKeywords map[string]struct{}) []string {
	// Filter out keywords that don't exist in pkg/detectors/*
	filteredKeywords := make(map[string]struct{})

	// Iterate through the input keys
	for _, key := range keys {
		// Check if the key contains any detectorKeyword
		for detectorKey := range detectorKeywords {
			if strings.Contains(strings.ToLower(key), detectorKey) {
				filteredKeywords[detectorKey] = struct{}{}
				break
			}
		}
	}

	filteredKeywordsSlice := make([]string, 0, len(filteredKeywords))
	for key := range filteredKeywords {
		filteredKeywordsSlice = append(filteredKeywordsSlice, key)
	}
	return filteredKeywordsSlice

}

// Used to filter out collections and environments that are not wanted for scanning.
func filterItemsByUUID(slice []IDNameUUID, uuidsToRemove []string, uuidsToInclude []string) []IDNameUUID {
	var result []IDNameUUID

	// Include takes precedence over exclude
	if uuidsToInclude != nil {
		// Create map of UUIDs to include for efficiency
		uuidSet := make(map[string]struct{})
		for _, uuid := range uuidsToInclude {
			uuidSet[uuid] = struct{}{}
		}

		// Iterate through the slice and add items that match the UUIDs to include
		for _, item := range slice {
			if _, exists := uuidSet[item.UUID]; exists {
				result = append(result, item)
			}
		}
		return result
	}

	if uuidsToRemove != nil {
		// Create map of UUIDs to remove for efficiency
		uuidSet := make(map[string]struct{})
		for _, uuid := range uuidsToRemove {
			uuidSet[uuid] = struct{}{}
		}

		// Iterate through the slice and add items that don't match the UUIDs to remove
		for _, item := range slice {
			if _, exists := uuidSet[item.UUID]; !exists {
				result = append(result, item)
			}
		}
		return result
	}

	return slice
}
