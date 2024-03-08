package postman

import (
	"fmt"
	"net/url"
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

	// Keywords are words that are discovered when we walk through postman data.
	// These keywords are then injected into data that is sent to the detectors.
	keywords []string
	sub      *Substitution

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
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

func (s *Source) subsSet(data string) string {
	matches := subRe.FindAllString(data, -1)
	replacements := []string{}
	for _, match := range matches {
		toReplace := s.sub.globalAndEnvSlice[match]
		for _, sub := range toReplace {
			if len(replacements) == 0 {
				replacements = append(replacements, strings.Replace(data, match, sub, -1))
			}

		}
	}

	return data
}

func (s *Source) subsSetHelper(data string, replacements *[]string) string {
	matches := subRe.FindAllString(data, -1)
	if len(matches) == 0 {
		*replacements = append(*replacements, data)
		return data
	}

	for _, match := range matches {
		trimmed := strings.Trim(match, "{}")
		toSub := s.sub.globalAndEnvSlice[trimmed]
		for _, sub := range toSub {
			data = s.subsSetHelper(strings.Replace(data, match, sub, -1), replacements)
			// fmt.Println("replaced", strings.Replace(data, match, sub, -1))
		}
	}

	return data
}

type Substitution struct {
	global     map[string]string
	env        map[string](map[string]string)
	collection map[string](map[string]string)

	globalAndEnvSlice map[string][]string
	collectionSlice   map[string](map[string][]string)
}

func NewSubstitution() *Substitution {
	return &Substitution{
		global:     make(map[string]string),
		env:        make(map[string](map[string]string)),
		collection: make(map[string](map[string]string)),

		globalAndEnvSlice: make(map[string][]string),
		collectionSlice:   make(map[string](map[string][]string)),
	}
}

// add adds a key-value pair to the substitution map.
// Note that there are only 3 types of substitutions: global, environment, and collection.
// This means users can define variables in any of these 3 scopes which can be used to subsitute
// in subsequent requests, responses, and events.
// Variables defined in requests, headers, etc can not be substituted in other requests, headers, etc.
func (sub *Substitution) add(metadata Metadata, key string, value string) {
	if metadata.Type == GLOBAL_TYPE || metadata.Type == ENVIRONMENT_TYPE {
		sub.global[key] = value
		sub.globalAndEnvSlice[key] = append(sub.globalAndEnvSlice[key], value)
	} else if metadata.Type == ENVIRONMENT_TYPE {
		if _, ok := sub.env[metadata.EnvironmentID]; !ok {
			sub.env[metadata.EnvironmentID] = make(map[string]string)
		}
		sub.env[metadata.EnvironmentID][key] = value
	} else if metadata.Type == COLLECTION_TYPE {
		if _, ok := sub.collection[metadata.CollectionInfo.PostmanID]; !ok {
			sub.collection[metadata.CollectionInfo.Description] = make(map[string]string)
			sub.collectionSlice[metadata.CollectionInfo.Description] = make(map[string][]string)
		}
		sub.collection[metadata.CollectionInfo.Description][key] = value
		sub.collectionSlice[metadata.CollectionInfo.Description][key] = append(sub.collectionSlice[metadata.CollectionInfo.Description][key], value)
	}
}

var subRe = regexp.MustCompile(`\{\{[^{}]+\}\}`)

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

	// s.scanVariableData(ctx, chunksChan, metadata, VariableData{
	// 	KeyValues: item.Variable,
	// })

}

func (s *Source) scanEvent(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, event Event) {
	metadata.Type = metadata.Type + " > event"

	// inject all the filtered keywords into the event data
	filteredKeywords := filterKeywords(s.keywords, s.detectorKeywords)
	data := strings.Join(filteredKeywords, " ")
	data += strings.Join(event.Script.Exec, " ")

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
		Data:           s.substitute(metadata, data),
	})
}

func (s *Source) keywordCombinations(str string) string {
	data := ""
	for _, keyword := range filterKeywords(s.keywords, s.detectorKeywords) {
		data += fmt.Sprintf("%s:%s\n ", keyword, str)
	}

	return data
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
		authData += s.keywordCombinations(apiKeyValue)
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
		authData += s.keywordCombinations(bearerValue)
	case "basic":
		keywords := filterKeywords(s.keywords, s.detectorKeywords)
		authData += strings.Join(keywords, " ") + "\n"
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
			authData += (s.substitute(m, decodedURL) + " ")
		}
	case "oauth2":
		for _, oauth := range auth.OAuth2 {
			switch oauth.Key {
			case "accessToken", "refreshToken", "clientId", "clientSecret", "accessTokenUrl", "authUrl":
				authData += fmt.Sprintf("%s:%v ", oauth.Key, oauth.Value)
				authData += s.keywordCombinations(fmt.Sprintf("%v", oauth.Value))
			}
		}
	case "noauth":
		return ""
	default:
		return ""
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
		Data:           s.substitute(m, authData),
	})

	return s.substitute(m, authData)
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
			Data:           s.substitute(metadata, r.URL.Raw),
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
			Data:           s.substitute(m, data),
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
			Data:           s.substitute(m, response.Body),
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
			s.sub.add(m, kv.Key, valStr)
		} else if kv.SessionValue != "" {
			valStr = fmt.Sprintf("%v", kv.SessionValue)
		}
		if valStr == "" {
			continue
		}
		// precendence goes env -> collection -> global
		values = append(values, s.substitute(m, valStr))
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
		Data:           data,
	}
	s.scanTarget(ctx, chunksChan, target)
}

func (s *Source) scanTarget(ctx context.Context, chunksChan chan *sources.Chunk, o Target) {
	if o.Data == "" {
		return
	}
	fmt.Println("----postman target-----")
	fmt.Println(o.Data)

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

func (s *Source) substitute(metadata Metadata, data string) string {
	return s.substituteM(metadata, data)
	// fmt.Println("returned subsset", s.subsSet(data))
	// // precendence goes env -> collection -> global
	// return subRe.ReplaceAllStringFunc(data, func(str string) string {
	// 	if val, ok := s.sub.env[metadata.EnvironmentID][strings.Trim(str, "{}")]; ok {
	// 		return val
	// 	}
	// 	if val, ok := s.sub.collection[metadata.CollectionInfo.PostmanID][strings.Trim(str, "{}")]; ok {
	// 		return val
	// 	}
	// 	if val, ok := s.sub.global[strings.Trim(str, "{}")]; ok {
	// 		return val
	// 	}
	// 	return str
	// })
}

func (s *Source) substituteM(metadata Metadata, data string) string {
	// precendence goes env -> collection -> global
	l := []string{}
	longest := 0
	matches := subRe.FindAllString(data, -1)
	for _, m := range matches {
		trimmed := strings.Trim(m, "{}")
		if len(s.sub.globalAndEnvSlice[trimmed]) > longest {
			longest = len(s.sub.globalAndEnvSlice[trimmed])
		}
	}

	// PICKUP HERE
	for i := 0; i < longest; i++ {
		d := subRe.ReplaceAllStringFunc(data, func(str string) string {
			if slice, ok := s.sub.globalAndEnvSlice[strings.Trim(str, "{}")]; ok {
				if i < len(slice) {
					return slice[i]
				} else {
					return slice[len(slice)-1]
				}
			}
			return str
		})
		l = append(l, d)
		// fmt.Println("bro what", d)
	}

	// return subRe.ReplaceAllStringFunc(data, func(str string) string {
	// 	if val, ok := s.sub.env[metadata.EnvironmentID][strings.Trim(str, "{}")]; ok {
	// 		return val
	// 	}
	// 	if val, ok := s.sub.collection[metadata.CollectionInfo.PostmanID][strings.Trim(str, "{}")]; ok {
	// 		return val
	// 	}
	// 	if val, ok := s.sub.global[strings.Trim(str, "{}")]; ok {
	// 		return val
	// 	}
	// 	return str
	// })
	return strings.Join(l, "\n")
}
