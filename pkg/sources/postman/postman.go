package postman

import (
	"fmt"
	"regexp"
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
	KEYWORD_PADDING  = 50
	GLOBAL_TYPE      = "globals"
	ENVIRONMENT_TYPE = "environment"
	REQUEST_TYPE     = "request"
	FOLDER_TYPE      = "folder"
	COLLECTION_TYPE  = "collection"
	EVENT_TYPE       = "script"

	SESSION_VALUE = "Session Value (hidden from UI)"
	INITIAL_VALUE = "Initial Value"
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

	// keywords are potential keywords
	keywords []string

	// each environment has a set of variables (key-value pairs)
	// variableSubstituions map[string]VariableData
	variableSubstituions map[string]VariableInfo

	// ZRNOTE: Talk about this first but what about if we just gathered all the keywords and all the values
	// _then_ sent it on the chunks channel rather than trying to do on the fly bookkeeping?
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

type VariableInfo struct {
	value     string
	source    string
	valueType string
}

// Target is a struct that holds the data for a single scan target.
// Not all fields are used for every scan target.
type Target struct {
	Link            string
	WorkspaceUUID   string
	WorkspaceName   string
	GlobalID        string
	CollectionID    string
	CollectionName  string
	EnvironmentID   string
	EnvironmentName string
	RequestID       string
	RequestName     string
	FolderId        string
	FolderName      string
	FieldType       string
	FieldName       string
	VarType         string
	Data            string
}

var subRe = regexp.MustCompile(`\{\{[^{}]+\}\}`)

// ToDo:
// 2. Read in local JSON files
// 3. Add tests
// 4. Try to filter out duplicate objects

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
	// s.collectionVariables = make(map[string]VariableData)
	s.variableSubstituions = make(map[string]VariableInfo)

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

	// scan per environment variables
	for _, envID := range workspace.Environments {
		env, err := s.client.GetEnvironment(envID.UUID)
		if err != nil {
			s.log.Error(err, "could not get environment object", "environment_uuid", envID.UUID)
		}
		// s.scanEnvironment(ctx, chunksChan, env, workspace)
		metadata.Type = ENVIRONMENT_TYPE
		metadata.Link = LINK_BASE_URL + ENVIRONMENT_TYPE + "/" + env.ID
		metadata.FullID = env.ID

		// scan environment
		vars := env.VariableData

		ctx.Logger().V(2).Info("scanning environment vars", "environment_uuid", metadata.FullID)
		for _, word := range strings.Split(vars.Name, " ") {
			s.keywords = append(s.keywords, string(word))
		}

		s.scanVariableData(ctx, chunksChan, metadata, vars)
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
	if collection.Variables != nil {
		s.scanVariableData(ctx, chunksChan, metadata, VariableData{
			KeyValues: collection.Variables,
		})
	}

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

	s.scanAuth(ctx, chunksChan, metadata, item.Auth, URL{})
	s.scanVariableData(ctx, chunksChan, metadata, VariableData{
		KeyValues: item.Variable,
	})

}

func (s *Source) scanEvent(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, event Event) {
	metadata.Type = metadata.Type + " > event"
	// for _, subMap := range *varSubMap {
	// 	data := strings.Join(event.Script.Exec, " ")

	// Prep direct links
	link := LINK_BASE_URL + metadata.Type + "/" + metadata.FullID
	if event.Listen == "prerequest" {
		link += "?tab=pre-request-scripts"
	} else {
		link += "?tab=tests"
	}

	s.scanTarget(ctx, chunksChan, Target{
		Link:           link,
		FieldType:      EVENT_TYPE,
		FieldName:      event.Listen,
		WorkspaceUUID:  metadata.WorkspaceUUID,
		WorkspaceName:  metadata.WorkspaceName,
		CollectionID:   metadata.CollectionInfo.PostmanID,
		CollectionName: metadata.CollectionInfo.Name,
		FolderName:     metadata.FolderName,
		FolderId:       metadata.FolderID,
		GlobalID:       metadata.FullID,
		// ZRNOTE: Todo
		// Data:           s.substitute(data, subMap),
	})
}

// Process Auth
func (s *Source) scanAuth(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, auth Auth, url URL) {
	var authData string
	switch auth.Type {
	case "apikey":
		authData = s.parseAPIKey(auth)
	case "awsSigV4":
		authData = s.parseAWSAuth(auth)
	case "bearer":
		authData = s.parseBearer(auth)
	case "basic":
		authData = s.parseBasicAuth(ctx, auth, url)
	case "noauth":
		authData = ""
	case "oauth2":
		authData = s.parseOAuth2(auth)
	default:
		return
	}

	s.scanTarget(ctx, chunksChan, Target{
		Link:           m.Link + "?tab=authorization",
		FieldType:      "Authorization",
		WorkspaceUUID:  m.WorkspaceUUID,
		WorkspaceName:  m.WorkspaceName,
		CollectionID:   m.CollectionInfo.PostmanID,
		CollectionName: m.CollectionInfo.Name,
		FolderName:     m.FolderName,
		FolderId:       m.FolderID,
		GlobalID:       m.FullID,
		Data:           authData,
	})
}

func (s *Source) scanHTTPRequest(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, r Request) {
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
		data := r.URL.Raw

		data = subRe.ReplaceAllStringFunc(data, func(str string) string {
			if val, ok := s.variableSubstituions[strings.Trim(str, "{}")]; ok {
				return val.value
			}
			return str
		})

		s.scanTarget(ctx, chunksChan, Target{
			Link:           metadata.Link,
			FieldType:      metadata.Type,
			WorkspaceUUID:  metadata.WorkspaceUUID,
			WorkspaceName:  metadata.WorkspaceName,
			CollectionID:   metadata.CollectionInfo.PostmanID,
			CollectionName: metadata.CollectionInfo.Name,
			FolderName:     metadata.FolderName,
			FolderId:       metadata.FolderID,
			RequestID:      metadata.RequestID,
			RequestName:    metadata.RequestName,
			GlobalID:       metadata.FullID,
			Data:           data,
		})
	}

	s.keywords = append(s.keywords, r.URL.Host...)

	if len(r.URL.Query) > 0 {
		vars := VariableData{
			KeyValues: r.URL.Query,
		}
		metadata.Type = metadata.Type + " > GET parameters (query)"
		s.scanVariableData(ctx, chunksChan, metadata, vars)
	}

	if r.Auth.Type != "" {
		metadata.Type = metadata.Type + " > request auth"
		s.scanAuth(ctx, chunksChan, metadata, r.Auth, URL{})
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
		// for _, subMap := range *varSubMap {
		// 	data += s.substitute(data, subMap)
		// }
		s.scanTarget(ctx, chunksChan, Target{
			Link:           m.Link,
			FieldType:      m.Type,
			WorkspaceUUID:  m.WorkspaceUUID,
			WorkspaceName:  m.WorkspaceName,
			CollectionID:   m.CollectionInfo.PostmanID,
			CollectionName: m.CollectionInfo.Name,
			FolderName:     m.FolderName,
			FolderId:       m.FolderID,
			RequestID:      m.RequestID,
			RequestName:    m.RequestName,
			GlobalID:       m.FullID,
			Data:           data,
		})
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
		s.scanTarget(ctx, chunksChan, Target{
			Link:           m.Link,
			FieldType:      m.Type,
			WorkspaceUUID:  m.WorkspaceUUID,
			WorkspaceName:  m.WorkspaceName,
			CollectionID:   m.CollectionInfo.PostmanID,
			CollectionName: m.CollectionInfo.Name,
			FolderName:     m.FolderName,
			FolderId:       m.FolderID,
			RequestID:      m.RequestID,
			RequestName:    m.RequestName,
			GlobalID:       m.FullID,
			Data:           response.Body,
		})
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
			if strings.HasPrefix(valStr, "{{") && strings.HasSuffix(valStr, "}}") {
				// This is a variable substitution. So we should see if there is any substitutions we can do
				// for this variable.
				// fmt.Println("valStr", valStr)
				valStr = strings.Trim(strings.Trim(valStr, "{"), "}")
				if val, ok := s.variableSubstituions[valStr]; ok {
					// If the value is a session value, we should not substitute it.
					// ZRNOTE: probably some collision here
					if val.valueType == INITIAL_VALUE {
						values = append(values, strings.TrimSpace(val.value))
					}
				}
			} else {
				s.variableSubstituions[kv.Key] = VariableInfo{
					value:     valStr,
					source:    m.Type,
					valueType: INITIAL_VALUE,
				}
				values = append(values, strings.TrimSpace(valStr))
			}
		}

		if kv.SessionValue != "" {
			sessionValue := fmt.Sprintf("%v", kv.SessionValue)
			s.keywords = append(s.keywords, sessionValue)
			if sessionValue == "" {
				continue
			}
			if strings.HasPrefix(sessionValue, "{{") && strings.HasSuffix(sessionValue, "}}") {
				// This is a variable substitution. So we should see if there is any substitutions we can do
				// for this variable.
				if val, ok := s.variableSubstituions[sessionValue]; ok {
					// If the value is a session value, we should not substitute it.
					// ZRNOTE: probably some collision here
					if val.valueType == SESSION_VALUE {
						sessionValue = val.value
						values = append(values, strings.TrimSpace(sessionValue))
					}
				}
			} else {
				s.variableSubstituions[kv.Key] = VariableInfo{
					value:     sessionValue,
					source:    m.Type,
					valueType: SESSION_VALUE,
				}
				values = append(values, strings.TrimSpace(sessionValue))
			}
		}
	}

	// Filter out keywords that don't exist in pkg/detectors/*
	filteredKeywords := filterKeywords(s.keywords, s.detectorKeywords)
	if len(filteredKeywords) == 0 || len(values) == 0 {
		return
	}

	data := ""
	for _, keyword := range filteredKeywords {
		for _, value := range values {
			data += fmt.Sprintf("%s:%s\n", keyword, value)
		}
		data += "\n\n"
	}

	target := Target{
		Link:           m.Link,
		WorkspaceUUID:  m.WorkspaceUUID,
		WorkspaceName:  m.WorkspaceName,
		CollectionID:   m.CollectionInfo.PostmanID,
		CollectionName: m.CollectionInfo.Name,
		GlobalID:       m.FullID,
		FieldType:      m.Type + " variable",
		// FieldName:      v.Key,
		// VarType:        v.Type,
		Data: data,
	}
	s.scanTarget(ctx, chunksChan, target)
}

func (s *Source) scanTarget(ctx context.Context, chunksChan chan *sources.Chunk, o Target) {
	if o.Data == "" {
		return
	}
	fmt.Println("#########START OBJECT#########")
	fmt.Println(o.Data)
	fmt.Println("#########END OBJECT#########")

	chunksChan <- &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		Data:       []byte(o.Data),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Postman{
				Postman: &source_metadatapb.Postman{
					Link:            o.Link,
					WorkspaceUuid:   o.WorkspaceUUID,
					WorkspaceName:   o.WorkspaceName,
					CollectionId:    o.CollectionID,
					CollectionName:  o.CollectionName,
					EnvironmentId:   o.EnvironmentID,
					EnvironmentName: o.EnvironmentName,
					RequestId:       o.RequestID,
					RequestName:     o.RequestName,
					FolderId:        o.FolderId,
					FolderName:      o.FolderName,
					FieldType:       o.FieldType,
					FieldName:       o.FieldName,
					VariableType:    o.VarType,
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
		lowerKey := strings.ToLower(key)
		for detectorKey := range detectorKeywords {
			if strings.Contains(lowerKey, detectorKey) {
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
