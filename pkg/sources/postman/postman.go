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
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/go-errors/errors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"

	"github.com/repeale/fp-go"
)

const (
	SourceType       = sourcespb.SourceType_SOURCE_TYPE_POSTMAN
	LINK_BASE_URL    = "https://go.postman.co/"
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

	metrics *metrics

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

func (s *Source) addKeywords(keywords []string) {
	for _, keyword := range keywords {
		s.attemptToAddKeyword(keyword)
	}
}

func (s *Source) attemptToAddKeyword(keyword string) {
	// fast check
	keyword = strings.ToLower(keyword)
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
	s.metrics = newMetrics(name)

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
		s.client = NewClient(conn.GetToken(), s.metrics)
		log.RedactGlobally(conn.GetToken())
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
		s.scanVariableData(ctx, chunksChan, Metadata{EnvironmentID: env.Id, EnvironmentName: env.Name, fromLocal: true, Link: envPath, LocationType: source_metadatapb.PostmanLocationType_ENVIRONMENT_VARIABLE}, env)
	}

	// Scan local collections
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
		workspace.Id = strings.TrimSuffix(basename, filepath.Ext(basename))
		s.scanLocalWorkspace(ctx, chunksChan, workspace, workspacePath)
	}

	// Scan workspaces
	for _, workspaceID := range s.conn.Workspaces {
		w, err := s.client.GetWorkspace(ctx, workspaceID)
		if err != nil {
			// Log and move on, because sometimes the Postman API seems to give us workspace IDs
			// that we don't have access to, so we don't want to kill the scan because of it.
			ctx.Logger().Error(err, "error getting workspace %s", workspaceID)
			continue
		}
		s.SetProgressOngoing(fmt.Sprintf("Scanning workspace %s", workspaceID), "")
		ctx.Logger().V(2).Info("scanning workspace from workspaces given", "workspace", workspaceID)
		if err = s.scanWorkspace(ctx, chunksChan, w); err != nil {
			return fmt.Errorf("error scanning workspace %s: %w", workspaceID, err)
		}
	}

	// Scan collections
	for _, collectionID := range s.conn.Collections {
		if shouldSkip(collectionID, s.conn.IncludeCollections, s.conn.ExcludeCollections) {
			continue
		}

		collection, err := s.client.GetCollection(ctx, collectionID)
		if err != nil {
			// Log and move on, because sometimes the Postman API seems to give us collection IDs
			// that we don't have access to, so we don't want to kill the scan because of it.
			ctx.Logger().Error(err, "error getting collection %s", collectionID)
			continue
		}
		s.SetProgressOngoing(fmt.Sprintf("Scanning collection %s", collectionID), "")
		s.scanCollection(ctx, chunksChan, Metadata{}, collection)
	}

	// Scan personal workspaces (from API token)
	if s.conn.Workspaces == nil && s.conn.Collections == nil && s.conn.Environments == nil && s.conn.GetToken() != "" {
		workspaces, err := s.client.EnumerateWorkspaces(ctx)
		if err != nil {
			return fmt.Errorf("error enumerating postman workspaces: %w", err)
		}
		ctx.Logger().V(2).Info("enumerated workspaces", "workspaces", workspaces)
		for _, workspace := range workspaces {
			s.SetProgressOngoing(fmt.Sprintf("Scanning workspace %s", workspace.Id), "")
			if err = s.scanWorkspace(ctx, chunksChan, workspace); err != nil {
				return fmt.Errorf("error scanning workspace %s: %w", workspace.Id, err)
			}
		}
	}

	s.SetProgressComplete(1, 1, "Completed scanning workspaces", "")
	return nil
}

func (s *Source) scanLocalWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspace Workspace, filePath string) {
	// reset keywords for each workspace
	s.resetKeywords()

	metadata := Metadata{
		WorkspaceUUID: workspace.Id,
		fromLocal:     true,
	}

	for _, environment := range workspace.EnvironmentsRaw {
		metadata.Link = strings.TrimSuffix(path.Base(filePath), path.Ext(filePath)) + "/environments/" + environment.Id + ".json"
		metadata.LocationType = source_metadatapb.PostmanLocationType_ENVIRONMENT_VARIABLE
		s.scanVariableData(ctx, chunksChan, metadata, environment)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}
	for _, collection := range workspace.CollectionsRaw {
		metadata.Link = strings.TrimSuffix(path.Base(filePath), path.Ext(filePath)) + "/collections/" + collection.Info.PostmanID + ".json"
		s.scanCollection(ctx, chunksChan, metadata, collection)
	}
}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspace Workspace) error {
	ctx.Logger().V(4).Info("scanning workspace",
		"workspace_id", workspace.Id,
		"collection_uids", fp.Map(func(i IdNameUid) string { return i.Uid })(workspace.Collections),
		"environment_uids", fp.Map(func(i IdNameUid) string { return i.Uid })(workspace.Environments),
		"collection_raw_uids", fp.Map(func(c Collection) string { return c.Info.Uid })(workspace.CollectionsRaw),
		"environment_raw_ids", fp.Map(func(v VariableData) string { return v.Id })(workspace.EnvironmentsRaw),
	)
	// reset keywords for each workspace
	s.resetKeywords()
	s.attemptToAddKeyword(workspace.Name)

	// initiate metadata to track the tree structure of postman data
	metadata := Metadata{
		WorkspaceUUID: workspace.Id,
		WorkspaceName: workspace.Name,
		CreatedBy:     workspace.CreatedBy,
		Type:          "workspace",
	}

	// gather and scan environment variables
	for _, envID := range workspace.Environments {
		envVars, err := s.client.GetEnvironmentVariables(ctx, envID.Uid)
		if err != nil {
			ctx.Logger().Error(err, "could not get env variables", "environment_uuid", envID.Uid)
			continue
		}
		if shouldSkip(envID.Uid, s.conn.IncludeEnvironments, s.conn.ExcludeEnvironments) {
			continue
		}
		metadata.Type = ENVIRONMENT_TYPE
		metadata.Link = LINK_BASE_URL + "environments/" + envID.Uid
		metadata.FullID = envVars.Id
		metadata.EnvironmentID = envID.Uid
		metadata.EnvironmentName = envVars.Name

		ctx.Logger().V(2).Info("scanning environment vars", "environment_uuid", metadata.FullID)
		for _, word := range strings.Split(envVars.Name, " ") {
			s.attemptToAddKeyword(word)
		}
		metadata.LocationType = source_metadatapb.PostmanLocationType_ENVIRONMENT_VARIABLE
		s.scanVariableData(ctx, chunksChan, metadata, envVars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
		metadata.Type = ""
		metadata.Link = ""
		metadata.FullID = ""
		metadata.EnvironmentID = ""
		metadata.EnvironmentName = ""
		ctx.Logger().V(2).Info("finished scanning environment vars", "environment_uuid", metadata.FullID)
	}
	ctx.Logger().V(2).Info("finished scanning environments")

	// scan all the collections in the workspace.
	// at this point we have all the possible
	// substitutions from Environment variables
	for _, collectionID := range workspace.Collections {
		if shouldSkip(collectionID.Uid, s.conn.IncludeCollections, s.conn.ExcludeCollections) {
			continue
		}
		collection, err := s.client.GetCollection(ctx, collectionID.Uid)
		if err != nil {
			// Log and move on, because sometimes the Postman API seems to give us collection IDs
			// that we don't have access to, so we don't want to kill the scan because of it.
			ctx.Logger().Error(err, "error getting collection %s", collectionID)
			continue
		}
		s.scanCollection(ctx, chunksChan, metadata, collection)
	}
	return nil
}

// scanCollection scans a collection and all its items, folders, and requests.
// locally scoped Metadata is updated as we drill down into the collection.
func (s *Source) scanCollection(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, collection Collection) {
	ctx = context.WithValues(ctx,
		"collection_name", collection.Info.Name,
		"collection_uuid", collection.Info.Uid,
	)
	ctx.Logger().V(2).Info("starting to scan collection",
		"variable_count", len(collection.Variables),
	)
	metadata.CollectionInfo = collection.Info
	metadata.Type = COLLECTION_TYPE
	s.attemptToAddKeyword(collection.Info.Name)

	if !metadata.fromLocal {
		metadata.FullID = metadata.CollectionInfo.Uid
		metadata.Link = LINK_BASE_URL + COLLECTION_TYPE + "/" + metadata.FullID
	}

	metadata.LocationType = source_metadatapb.PostmanLocationType_COLLECTION_VARIABLE
	// variables must be scanned first before drilling down into the folders and events
	// because we need to pick up the substitutions from the top level collection variables
	s.scanVariableData(ctx, chunksChan, metadata, VariableData{
		KeyValues: collection.Variables,
	})
	metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN

	// collections don't have URLs in the Postman API, but we can scan the Authorization section without it.
	s.scanAuth(ctx, chunksChan, metadata, collection.Auth, URL{})

	ctx.Logger().V(3).Info("Scanning events in collection",
		"event_count", len(collection.Events),
	)
	for _, event := range collection.Events {
		s.scanEvent(ctx, chunksChan, metadata, event)
	}

	ctx.Logger().V(3).Info("Scanning items in collection",
		"item_ids", fp.Map(func(i Item) string { return i.Id })(collection.Items),
	)
	for _, item := range collection.Items {
		seenItemIds := make(map[string]struct{})
		s.scanItem(ctx, chunksChan, collection, metadata, item, "", seenItemIds)
	}
}

func (s *Source) scanItem(ctx context.Context, chunksChan chan *sources.Chunk, collection Collection, metadata Metadata, item Item, parentItemId string, seenItemIds map[string]struct{}) {
	ctx = context.WithValue(ctx, "item_uid", item.Uid)

	ctx.Logger().V(3).Info("Starting to scan item",
		"item_parent_item_id", parentItemId,
		"item_descendent_item_uids", fp.Map(func(i Item) string { return i.Uid })(item.Items),
		"item_event_count", len(item.Events),
		"item_response_count", len(item.Response),
		"item_variable_count", len(item.Variable),
	)

	seenItemIds[item.Uid] = struct{}{}

	s.attemptToAddKeyword(item.Name)

	// override the base collection metadata with item-specific metadata
	metadata.Type = FOLDER_TYPE
	if metadata.FolderName != "" {
		// keep track of the folder hierarchy
		metadata.FolderName = metadata.FolderName + " > " + item.Name
	} else {
		metadata.FolderName = item.Name
	}

	if item.Uid != "" {
		metadata.FullID = item.Uid
		metadata.Link = LINK_BASE_URL + FOLDER_TYPE + "/" + metadata.FullID
	}
	// recurse through the folders
	for _, subItem := range item.Items {
		if _, ok := seenItemIds[subItem.Uid]; ok {
			ctx.Logger().Info("Skipping already-seen item",
				"seen_item_id", subItem.Uid,
			)
			continue
		}
		s.scanItem(ctx, chunksChan, collection, metadata, subItem, item.Uid, seenItemIds)
	}

	// The assignment of the folder ID to be the current item UID is due to wanting to assume that your current item is a folder unless you have request data inside of your item.
	// If your current item is a folder, you will want the folder ID to match the UID of the current item.
	// If your current item is a request, you will want the folder ID to match the UID of the parent folder.
	// If the request is at the root of a collection and has no parent folder, the folder ID will be empty.
	metadata.FolderID = item.Uid
	// check if there are any requests in the folder
	if item.Request.Method != "" {
		metadata.FolderName = strings.Replace(metadata.FolderName, (" > " + item.Name), "", -1)
		metadata.FolderID = parentItemId
		if metadata.FolderID == "" {
			metadata.FolderName = ""
		}
		metadata.RequestID = item.Uid
		metadata.RequestName = item.Name
		metadata.Type = REQUEST_TYPE
		if item.Uid != "" {
			// Route to API endpoint
			metadata.FullID = item.Uid
			metadata.Link = LINK_BASE_URL + REQUEST_TYPE + "/" + item.Uid
		} else {
			// Route to collection.json
			metadata.FullID = item.Id
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
	metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN

	ctx.Logger().V(3).Info("Finished scanning item", "item_uid", item.Uid)
}

func (s *Source) scanEvent(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, event Event) {
	metadata.Type = metadata.Type + " > event"
	data := strings.Join(event.Script.Exec, " ")

	// Prep direct links. Ignore updating link if it's a local JSON file
	if !metadata.fromLocal {
		metadata.Link = LINK_BASE_URL + (strings.Replace(metadata.Type, " > event", "", -1)) + "/" + metadata.FullID
		if event.Listen == "prerequest" {
			metadata.Link += "?tab=pre-request-scripts"
		} else {
			metadata.Link += "?tab=tests"
		}
	}

	if strings.Contains(metadata.Type, REQUEST_TYPE) {
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_SCRIPT
	} else if strings.Contains(metadata.Type, FOLDER_TYPE) {
		metadata.LocationType = source_metadatapb.PostmanLocationType_FOLDER_SCRIPT
	} else if strings.Contains(metadata.Type, COLLECTION_TYPE) {
		metadata.LocationType = source_metadatapb.PostmanLocationType_COLLECTION_SCRIPT
	}

	ctx = context.WithValue(ctx, "event_listen", event.Listen)
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, metadata, data, DefaultMaxRecursionDepth)), metadata)
	metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
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
		if strings.Contains(m.Type, REQUEST_TYPE) {
			m.Link += "?tab=auth"
		} else {
			m.Link += "?tab=authorization"
		}
		m.Type += " > authorization"
	}

	s.attemptToAddKeyword(authData)

	m.FieldType = AUTH_TYPE

	if strings.Contains(m.Type, REQUEST_TYPE) {
		m.LocationType = source_metadatapb.PostmanLocationType_REQUEST_AUTHORIZATION
	} else if strings.Contains(m.Type, FOLDER_TYPE) {
		m.LocationType = source_metadatapb.PostmanLocationType_FOLDER_AUTHORIZATION
	} else if strings.Contains(m.Type, COLLECTION_TYPE) {
		m.LocationType = source_metadatapb.PostmanLocationType_COLLECTION_AUTHORIZATION
	}
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, m, authData, DefaultMaxRecursionDepth)), m)
	m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
}

func (s *Source) scanHTTPRequest(ctx context.Context, chunksChan chan *sources.Chunk, metadata Metadata, r Request) {
	ctx.Logger().V(3).Info("scanning http request",
		"request_header_count", len(r.HeaderKeyValue),
		"request_has_string_header", r.HeaderString == nil,
		"request_url_query_param_count", len(r.URL.Query),
		"request_url_path_param_count", len(r.URL.Path),
	)

	s.addKeywords(r.URL.Host)
	originalType := metadata.Type

	// Add in var procesisng for headers
	if r.HeaderKeyValue != nil {
		vars := VariableData{
			KeyValues: r.HeaderKeyValue,
		}
		metadata.Type = originalType + " > header"
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_HEADER
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if r.HeaderString != nil {
		metadata.Type = originalType + " > header"
		metadata.Link = metadata.Link + "?tab=headers"
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_HEADER
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, metadata, strings.Join(r.HeaderString, " "), DefaultMaxRecursionDepth)), metadata)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if r.URL.Raw != "" {
		metadata.Type = originalType + " > request URL (no query parameters)"
		// Note: query parameters are handled separately
		u := fmt.Sprintf("%s://%s/%s", r.URL.Protocol, strings.Join(r.URL.Host, "."), strings.Join(r.URL.Path, "/"))
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_URL
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, metadata, u, DefaultMaxRecursionDepth)), metadata)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if len(r.URL.Query) > 0 {
		vars := VariableData{
			KeyValues: r.URL.Query,
		}
		metadata.Type = originalType + " > GET parameters (query)"
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_QUERY_PARAMETER
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if r.Auth.Type != "" {
		metadata.Type = originalType + " > request auth"
		s.scanAuth(ctx, chunksChan, metadata, r.Auth, r.URL)
	}

	if r.Body.Mode != "" {
		metadata.Type = originalType + " > body"
		s.scanRequestBody(ctx, chunksChan, metadata, r.Body)
	}
}

func (s *Source) scanRequestBody(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, b Body) {
	ctx.Logger().V(3).Info("scanning request body",
		"request_body_form_data_count", len(b.FormData),
		"request_body_url_encoded_param_count", len(b.URLEncoded),
	)
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
		m.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_FORM_DATA
		s.scanVariableData(ctx, chunksChan, m, vars)
		m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	case "urlencoded":
		m.Type = originalType + " > url encoded"
		vars := VariableData{
			KeyValues: b.URLEncoded,
		}
		m.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_URL_ENCODED
		s.scanVariableData(ctx, chunksChan, m, vars)
		m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	case "raw":
		m.Type = originalType + " > raw"
		data := b.Raw
		m.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_RAW
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, m, data, DefaultMaxRecursionDepth)), m)
		m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	case "graphql":
		m.Type = originalType + " > graphql"
		data := b.GraphQL.Query + " " + b.GraphQL.Variables
		m.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_GRAPHQL
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, m, data, DefaultMaxRecursionDepth)), m)
		m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}
}

func (s *Source) scanHTTPResponse(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, response Response) {
	if response.Uid != "" {
		m.Link = LINK_BASE_URL + "example/" + response.Uid
		m.FullID = response.Uid
	}
	originalType := m.Type

	if response.HeaderKeyValue != nil {
		vars := VariableData{
			KeyValues: response.HeaderKeyValue,
		}
		m.Type = originalType + " > response header"
		m.LocationType = source_metadatapb.PostmanLocationType_RESPONSE_HEADER
		s.scanVariableData(ctx, chunksChan, m, vars)
		m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if response.HeaderString != nil {
		m.Type = originalType + " > response header"
		// TODO Note: for now, links to Postman responses do not include a more granular tab for the params/header/body, but when they do, we will need to update the metadata.Link info
		m.LocationType = source_metadatapb.PostmanLocationType_RESPONSE_HEADER
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, m, strings.Join(response.HeaderString, " "), DefaultMaxRecursionDepth)), m)
		m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	// Body in a response is just a string
	if response.Body != "" {
		m.Type = originalType + " > response body"
		m.LocationType = source_metadatapb.PostmanLocationType_RESPONSE_BODY
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(ctx, m, response.Body, DefaultMaxRecursionDepth)), m)
		m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if response.OriginalRequest.Method != "" {
		m.Type = originalType + " > original request"
		s.scanHTTPRequest(ctx, chunksChan, m, response.OriginalRequest)
	}
}

func (s *Source) scanVariableData(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, variableData VariableData) {
	if len(variableData.KeyValues) == 0 {
		ctx.Logger().V(2).Info("no variables to scan", "type", m.Type, "item_uuid", m.FullID)
		return
	}

	if !m.fromLocal && m.Type == COLLECTION_TYPE {
		m.Link += "?tab=variables"
	}

	values := []string{}
	for _, kv := range variableData.KeyValues {
		s.attemptToAddKeyword(kv.Key)
		valStr := fmt.Sprintf("%v", kv.Value)
		s.attemptToAddKeyword(valStr)
		if valStr != "" {
			s.sub.add(m, kv.Key, valStr)
		} else if kv.SessionValue != "" {
			valStr = fmt.Sprintf("%v", kv.SessionValue)
		}
		if valStr == "" {
			continue
		}
		values = append(values, s.buildSubstituteSet(ctx, m, valStr, DefaultMaxRecursionDepth)...)
	}

	m.FieldType = m.Type + " variables"
	switch m.FieldType {
	case "request > GET parameters (query) variables":
		m.Link = m.Link + "?tab=params"
	case "request > header variables":
		m.Link = m.Link + "?tab=headers"
	}
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(values), m)
}

func (s *Source) scanData(ctx context.Context, chunksChan chan *sources.Chunk, data string, metadata Metadata) {
	if data == "" {
		ctx.Logger().V(3).Info("Data string is empty", "workspace_id", metadata.WorkspaceUUID)
		return
	}
	if metadata.FieldType == "" {
		metadata.FieldType = metadata.Type
	}

	ctx.Logger().V(3).Info("Generating chunk and passing it to the channel", "link", metadata.Link)
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
					CollectionId:    metadata.CollectionInfo.Uid,
					CollectionName:  metadata.CollectionInfo.Name,
					EnvironmentId:   metadata.EnvironmentID,
					EnvironmentName: metadata.EnvironmentName,
					RequestId:       metadata.RequestID,
					RequestName:     metadata.RequestName,
					FolderId:        metadata.FolderID,
					FolderName:      metadata.FolderName,
					FieldType:       metadata.FieldType,
					LocationType:    metadata.LocationType,
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
		defer rc.Close()
		contents, err := io.ReadAll(rc)
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
