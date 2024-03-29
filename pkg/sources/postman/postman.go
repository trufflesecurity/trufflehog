package postman

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/go-errors/errors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
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
	client           *Client
	conn             *sourcespb.Postman
	DetectorKeywords map[string]struct{}

	// Keywords are words that are discovered when we walk through postman data.
	// These keywords are then injected into data that is sent to the detectors.
	keywords map[string]struct{}
	sub      *Substitution

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

func (s *Source) addKeywords(keywords []string) {
	for _, keyword := range keywords {
		s.addKeyword(keyword)
	}
}

func (s *Source) addKeyword(keyword string) {
	// fast check
	if _, ok := s.DetectorKeywords[keyword]; ok {
		s.keywords[keyword] = struct{}{}
		return
	}

	// slow check. This is to handle the case where the keyword is a substring of a detector keyword
	// e.g. "datadog-token" is a variable key in postman, but "datadog" is a detector keyword
	for k := range s.DetectorKeywords {
		if strings.Contains(keyword, k) {
			s.keywords[k] = struct{}{}
		}
	}
}

func (s *Source) resetKeywords() {
	s.keywords = make(map[string]struct{})
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
	s.keywords = make(map[string]struct{})
	s.sub = NewSubstitution()

	var conn sourcespb.Postman
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.conn = &conn

	switch conn.Credential.(type) {
	case *sourcespb.Postman_Token:
		if conn.GetToken() == "" {
			return errors.New("Postman token is empty")
		}
		s.client = NewClient(conn.GetToken())
		s.client.HTTPClient = common.RetryableHTTPClientTimeout(3)
	case *sourcespb.Postman_Unauthenticated:
		s.client = nil
		// No client needed if reading from local
	default:
		return errors.New("credential type not implemented for Postman")
	}

	return nil
}

// Chunks scans the Postman source and sends the data to the chunks chan.
// It scans the local environment, collection, and workspace files, and then scans the Postman API if a token is provided.
// The Postman source is different to our other sources in that we are not relying on the data we read from the source to contain
// all the information we need to scan, i.e, a git chunk contains all the information needed to check if a secret is present in that chunk.
// Postman on the other hand requires us to build context (the keywords and variables) as we scan the data.
// Check out the postman UI to see what I mean.
// Metadata is used to track information that informs the source of the chunk (e.g. the workspace -> collection -> request -> variable hierarchy).
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	// Scan local environments
	for _, envPath := range s.conn.EnvironmentPaths {
		env := VariableData{}
		contents, err := os.ReadFile(envPath)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(contents, &env); err != nil {
			return err
		}
		s.scanVariableData(ctx, chunksChan, Metadata{EnvironmentName: env.ID, fromLocal: true, Link: envPath}, env)
	}

	// Scan local workspaces
	for _, collectionPath := range s.conn.CollectionPaths {
		collection := Collection{}
		contents, err := os.ReadFile(collectionPath)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(contents, &collection); err != nil {
			return err
		}
		s.scanCollection(ctx, chunksChan, Metadata{CollectionInfo: collection.Info, fromLocal: true, Link: collectionPath}, collection)
	}

	// Scan local workspaces
	for _, workspacePath := range s.conn.WorkspacePaths {
		// check if zip file
		workspace := Workspace{}
		if strings.HasSuffix(workspacePath, ".zip") {
			var err error
			workspace, err = unpackWorkspace(workspacePath)
			if err != nil {
				return err
			}
		}
		basename := path.Base(workspacePath)
		workspace.ID = strings.TrimSuffix(basename, filepath.Ext(basename))
		s.scanLocalWorkspace(ctx, chunksChan, workspace, workspacePath)
	}

	// Scan workspaces
	for _, workspaceID := range s.conn.Workspaces {
		w, err := s.client.GetWorkspace(workspaceID)
		if err != nil {
			return fmt.Errorf("error getting workspace %s: %w", workspaceID, err)
		}
		if err = s.scanWorkspace(ctx, chunksChan, w); err != nil {
			return fmt.Errorf("error scanning workspace %s: %w", workspaceID, err)
		}
	}

	// Scan collections
	for _, collectionID := range s.conn.Collections {
		if shouldSkip(collectionID, s.conn.IncludeCollections, s.conn.ExcludeCollections) {
			continue
		}

		collection, err := s.client.GetCollection(collectionID)
		if err != nil {
			return fmt.Errorf("error getting collection %s: %w", collectionID, err)
		}
		s.scanCollection(ctx, chunksChan, Metadata{}, collection)
	}

	// Scan personal workspaces (from API token)
	if s.conn.Workspaces == nil && s.conn.Collections == nil && s.conn.Environments == nil && s.conn.GetToken() != "" {
		workspaces, err := s.client.EnumerateWorkspaces()
		if err != nil {
			return fmt.Errorf("error enumerating postman workspaces: %w", err)
		}
		for _, workspace := range workspaces {
			if err = s.scanWorkspace(ctx, chunksChan, workspace); err != nil {
				return fmt.Errorf("error scanning workspace %s: %w", workspace.ID, err)
			}
		}
	}

	return nil
}

func (s *Source) scanLocalWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspace Workspace, filePath string) {
	// reset keywords for each workspace
	s.resetKeywords()

	metadata := Metadata{
		WorkspaceUUID: workspace.ID,
		fromLocal:     true,
	}

	for _, environment := range workspace.EnvironmentsRaw {
		metadata.Link = strings.TrimSuffix(path.Base(filePath), path.Ext(filePath)) + "/environments/" + environment.ID + ".json"
		s.scanVariableData(ctx, chunksChan, metadata, environment)
	}
	for _, collection := range workspace.CollectionsRaw {
		metadata.Link = strings.TrimSuffix(path.Base(filePath), path.Ext(filePath)) + "/collections/" + collection.Info.PostmanID + ".json"
		s.scanCollection(ctx, chunksChan, metadata, collection)
	}
}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspace Workspace) error {
	// reset keywords for each workspace
	s.resetKeywords()
	s.addKeyword(workspace.Name)

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
		return fmt.Errorf("error getting global variables for workspace %s, %w", workspace.ID, err)
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
			ctx.Logger().Error(err, "could not get env variables", "environment_uuid", envID.UUID)
			continue
		}
		if shouldSkip(envID.UUID, s.conn.IncludeEnvironments, s.conn.ExcludeEnvironments) {
			continue
		}
		metadata.Type = ENVIRONMENT_TYPE
		metadata.Link = LINK_BASE_URL + "environments/" + envID.UUID
		metadata.FullID = envVars.ID
		metadata.EnvironmentID = envID.UUID

		ctx.Logger().V(2).Info("scanning environment vars", "environment_uuid", metadata.FullID)
		for _, word := range strings.Split(envVars.Name, " ") {
			s.addKeyword(word)
		}

		s.scanVariableData(ctx, chunksChan, metadata, envVars)
		ctx.Logger().V(2).Info("finished scanning environment vars", "environment_uuid", metadata.FullID)
	}
	ctx.Logger().V(2).Info("finished scanning environments")

	// scan all the collections in the workspace.
	// at this point we have all the possible
	// substitutions from Global and Environment variables
	for _, collectionID := range workspace.Collections {
		if shouldSkip(collectionID.UUID, s.conn.IncludeCollections, s.conn.ExcludeCollections) {
			continue
		}
		collection, err := s.client.GetCollection(collectionID.UUID)
		if err != nil {
			return err
		}
		s.scanCollection(ctx, chunksChan, metadata, collection)
	}
	return nil
}

// scanCollection scans a collection and all its items, folders, and requests.
// locally scoped Metadata is updated as we drill down into the collection.
func (s *Source) scanCollection(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, collection Collection) {
	ctx.Logger().V(2).Info("starting scanning collection", collection.Info.Name, "uuid", collection.Info.UID)
	metadata.CollectionInfo = collection.Info
	metadata.Type = COLLECTION_TYPE
	s.addKeyword(collection.Info.Name)

	if !metadata.fromLocal {
		metadata.FullID = metadata.CollectionInfo.UID
		metadata.Link = LINK_BASE_URL + COLLECTION_TYPE + "/" + metadata.FullID
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

func (s *Source) scanItem(ctx context.Context, chunksChan chan *sources.Chunk, collection Collection, metadata Metadata, item Item) {
	s.addKeyword(item.Name)

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

	// Prep direct links. Ignore updating link if it's a local JSON file
	if !metadata.fromLocal {
		metadata.Link = LINK_BASE_URL + metadata.Type + "/" + metadata.FullID
		if event.Listen == "prerequest" {
			metadata.Link += "?tab=pre-request-scripts"
		} else {
			metadata.Link += "?tab=tests"
		}
	}

	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstitueSet(metadata, data)), metadata)
}

func (s *Source) scanAuth(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, auth Auth, u URL) {
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
				return
			}

			parsedURL.User = url.User(username + ":" + password)
			decodedURL, err := url.PathUnescape(parsedURL.String())
			if err != nil {
				ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
				return
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
		return
	default:
		return
	}

	if !m.fromLocal {
		m.Link += "?tab=auth"
		m.Type += " > authorization"
	}

	m.FieldType = AUTH_TYPE
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstitueSet(m, authData)), m)
}

func (s *Source) scanHTTPRequest(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, r Request) {
	s.addKeywords(r.URL.Host)
	originalType := metadata.Type

	// Add in var procesisng for headers
	if r.Header != nil {
		vars := VariableData{
			KeyValues: r.Header,
		}
		metadata.Type = originalType + " > header"
		s.scanVariableData(ctx, chunksChan, metadata, vars)
	}

	if r.URL.Raw != "" {
		metadata.Type = originalType + " > request URL (no query parameters)"
		// Note: query parameters are handled separately
		u := fmt.Sprintf("%s://%s/%s", r.URL.Protocol, strings.Join(r.URL.Host, "."), strings.Join(r.URL.Path, "/"))
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstitueSet(metadata, u)), metadata)
	}

	if len(r.URL.Query) > 0 {
		vars := VariableData{
			KeyValues: r.URL.Query,
		}
		metadata.Type = originalType + " > GET parameters (query)"
		s.scanVariableData(ctx, chunksChan, metadata, vars)
	}

	if r.Auth.Type != "" {
		metadata.Type = originalType + " > request auth"
		s.scanAuth(ctx, chunksChan, metadata, r.Auth, r.URL)
	}

	if r.Body.Mode != "" {
		metadata.Type = originalType + " > body"
		s.scanBody(ctx, chunksChan, metadata, r.Body)
	}
}

func (s *Source) scanBody(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, b Body) {
	if !m.fromLocal {
		m.Link = m.Link + "?tab=body"
	}
	originalType := m.Type
	switch b.Mode {
	case "formdata":
		m.Type = originalType + " > form data"
		vars := VariableData{
			KeyValues: b.FormData,
		}
		s.scanVariableData(ctx, chunksChan, m, vars)
	case "urlencoded":
		m.Type = originalType + " > url encoded"
		vars := VariableData{
			KeyValues: b.URLEncoded,
		}
		s.scanVariableData(ctx, chunksChan, m, vars)
	case "raw", "graphql":
		data := b.Raw
		if b.Mode == "graphql" {
			m.Type = originalType + " > graphql"
			data = b.GraphQL.Query + " " + b.GraphQL.Variables
		}
		if b.Mode == "raw" {
			m.Type = originalType + " > raw"
		}
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstitueSet(m, data)), m)
	default:
		break
	}
}

func (s *Source) scanHTTPResponse(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, response Response) {
	if response.UID != "" {
		m.Link = LINK_BASE_URL + "example/" + response.UID
		m.FullID = response.UID
	}
	originalType := m.Type

	if response.Header != nil {
		vars := VariableData{
			KeyValues: response.Header,
		}
		m.Type = originalType + " > response header"
		s.scanVariableData(ctx, chunksChan, m, vars)
	}

	// Body in a response is just a string
	if response.Body != "" {
		m.Type = originalType + " > response body"
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstitueSet(m, response.Body)), m)
	}

	if response.OriginalRequest.Method != "" {
		m.Type = originalType + " > original request"
		s.scanHTTPRequest(ctx, chunksChan, m, response.OriginalRequest)
	}
}

func (s *Source) scanVariableData(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, variableData VariableData) {
	if len(variableData.KeyValues) == 0 {
		ctx.Logger().V(2).Info("no variables to scan", "type", m.Type, "uuid", m.FullID)
		return
	}

	if !m.fromLocal && m.Type == COLLECTION_TYPE {
		m.Link += "?tab=variables"
	}

	values := []string{}
	for _, kv := range variableData.KeyValues {
		s.addKeyword(kv.Key)
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
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(values), m)
}

func (s *Source) scanData(ctx context.Context, chunksChan chan *sources.Chunk, data string, metadata Metadata) {
	if data == "" {
		return
	}
	metadata.FieldType = metadata.Type

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
					CollectionId:    metadata.CollectionInfo.UID,
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

// unpackWorkspace unzips the provided zip file and scans the inflated files
// for collections and environments. It populates the CollectionsRaw and
// EnvironmentsRaw fields of the Workspace object.
func unpackWorkspace(workspacePath string) (Workspace, error) {
	var workspace Workspace
	r, err := zip.OpenReader(workspacePath)
	if err != nil {
		return workspace, err
	}
	defer r.Close()
	for _, file := range r.File {
		rc, err := file.Open()
		if err != nil {
			return workspace, err
		}
		contents, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return workspace, err
		}
		if strings.Contains(file.Name, "collection") {
			// read in the collection then scan it
			var c Collection
			if err = json.Unmarshal(contents, &c); err != nil {
				return workspace, err
			}
			workspace.CollectionsRaw = append(workspace.CollectionsRaw, c)
		}
		if strings.Contains(file.Name, "environment") {
			var e VariableData
			if err = json.Unmarshal(contents, &e); err != nil {
				return workspace, err
			}
			workspace.EnvironmentsRaw = append(workspace.EnvironmentsRaw, e)
		}
	}
	return workspace, nil
}

func shouldSkip(uuid string, include []string, exclude []string) bool {
	if slices.Contains(exclude, uuid) {
		return true
	}
	if len(include) > 0 && !slices.Contains(include, uuid) {
		return true
	}
	return false
}
