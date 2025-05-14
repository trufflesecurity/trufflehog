package postman

import (
	"fmt"
	"github.com/repeale/fp-go"
	neturl "net/url"
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
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// This is mostly a convenience struct to hold things we'll get from a
// bunch of different places in a single type.
type VariableDatum struct {
	Key          string
	Value        string
	SessionValue string
}

const (
	SourceType       = sourcespb.SourceType_SOURCE_TYPE_POSTMAN
	LINK_BASE_URL    = "https://go.postman.co/"
	ENVIRONMENT_TYPE = "environment"
	AUTH_TYPE        = "authorization"
	REQUEST_TYPE     = "request"
	FOLDER_TYPE      = "folder"
	COLLECTION_TYPE  = "collection"
)

type Source struct {
	name             string
	sourceId         sources.SourceID
	jobId            sources.JobID
	verify           bool
	apiClient        *postmanApiClient
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
func (s *Source) Init(_ context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, _ int) error {
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
		s.apiClient = NewPostmanApiClient(conn.GetToken())
		// TODO - Move this into the client itself.  It shouldn't be here
		s.apiClient.httpClient = common.RetryableHTTPClientTimeout(10)
		log.RedactGlobally(conn.GetToken())
	case *sourcespb.Postman_Unauthenticated:
		s.apiClient = nil
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
		contents, err := os.ReadFile(envPath)
		if err != nil {
			return err
		}
		environment, err := GetEnvironmentFromJsonBytes(contents)
		if err != nil {
			return err
		}
		vars := fp.Map(func(p struct{ Key, Value, SessionValue string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value}
		})(environment.KeyValues)
		s.scanVariableData(
			ctx,
			chunksChan,
			PostmanMetadata{
				EnvironmentUid:  environment.Uid,
				EnvironmentName: environment.Name,
				fromLocal:       true,
				Link:            envPath,
				LocationType:    source_metadatapb.PostmanLocationType_ENVIRONMENT_VARIABLE},
			vars)
	}

	// Scan local collections
	for _, collectionPath := range s.conn.CollectionPaths {
		contents, err := os.ReadFile(collectionPath)
		if err != nil {
			return err
		}
		collection, err := GetCollectionFromJsonBytes(contents)
		if err != nil {
			return err
		}
		s.scanCollection(
			ctx,
			chunksChan,
			PostmanMetadata{CollectionUid: collection.Uid, CollectionName: collection.Name, fromLocal: true, Link: collectionPath},
			collection)
	}

	// Scan local workspaces
	// TODO - This is broken, fix it
	for _, workspacePath := range s.conn.WorkspacePaths {
		// check if zip file
		if strings.HasSuffix(workspacePath, ".zip") {
			fileReadOutput, err := unpackWorkspace(workspacePath)
			if err != nil {
				return err
			}
			basename := path.Base(workspacePath)
			workspaceId := strings.TrimSuffix(basename, filepath.Ext(basename))
			s.scanLocalWorkspace(ctx, chunksChan, workspaceId, fileReadOutput, workspacePath)
		}
	}

	// Scan workspaces
	for _, workspaceID := range s.conn.Workspaces {
		w, err := s.apiClient.GetWorkspaceById(ctx, workspaceID)
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
	for _, collectionUid := range s.conn.Collections {
		if shouldSkip(collectionUid, s.conn.IncludeCollections, s.conn.ExcludeCollections) {
			continue
		}

		collection, err := s.apiClient.GetCollectionByUid(ctx, collectionUid)
		if err != nil {
			// Log and move on, because sometimes the Postman API seems to give us collection IDs
			// that we don't have access to, so we don't want to kill the scan because of it.
			ctx.Logger().Error(err, "error getting collection with uid %s", collectionUid)
			continue
		}
		s.SetProgressOngoing(fmt.Sprintf("Scanning collection with uid %s", collectionUid), "")
		s.scanCollection(ctx, chunksChan, PostmanMetadata{}, collection)
	}

	// Scan personal workspaces (from API token)
	if s.conn.Workspaces == nil && s.conn.Collections == nil && s.conn.Environments == nil && s.conn.GetToken() != "" {
		workspaceSummaries, err := s.apiClient.GetWorkspaceSummaryList(ctx)
		if err != nil {
			return fmt.Errorf("error enumerating postman workspaces: %w", err)
		}
		ctx.Logger().V(2).Info("enumerated workspaces", "workspaces", workspaceSummaries)
		for _, workspace_summary := range workspaceSummaries {
			s.SetProgressOngoing(fmt.Sprintf("Scanning workspace with id %s", workspace_summary.Id), "")

			// Get the full workspace information
			workspace, err := s.apiClient.GetWorkspaceById(ctx, workspace_summary.Id)
			if err != nil {
				return fmt.Errorf("error getting workspace info with id: %s, %v", workspace_summary.Id, err)
			}

			if err = s.scanWorkspace(ctx, chunksChan, workspace); err != nil {
				return fmt.Errorf("error scanning workspace %s: %w", workspace_summary.Id, err)
			}
		}
	}

	s.SetProgressComplete(1, 1, "Completed scanning workspaces", "")
	return nil
}

func (s *Source) scanLocalWorkspace(
	ctx context.Context,
	chunksChan chan *sources.Chunk,
	workspaceId string,
	fileReadOutput PostmanProcessedFile,
	filePath string,
) {
	// reset keywords for each workspace
	s.resetKeywords()

	metadata := PostmanMetadata{
		WorkspaceId: workspaceId,
		fromLocal:   true,
	}

	for _, environment := range fileReadOutput.Environments {
		metadata.Link = strings.TrimSuffix(path.Base(filePath), path.Ext(filePath)) + "/environments/" + environment.Uid + ".json"
		metadata.LocationType = source_metadatapb.PostmanLocationType_ENVIRONMENT_VARIABLE
		vars := fp.Map(func(p struct{ Key, Value, SessionValue string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value, SessionValue: p.SessionValue}
		})(environment.KeyValues)
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}
	for _, collection := range fileReadOutput.Collections {
		metadata.Link = strings.TrimSuffix(path.Base(filePath), path.Ext(filePath)) + "/collections/" + collection.Uid + ".json"
		s.scanCollection(ctx, chunksChan, metadata, collection)
	}
}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspace PostmanWorkspace) error {
	// reset keywords for each workspace
	s.resetKeywords()
	s.attemptToAddKeyword(workspace.Name)

	// initiate metadata to track the tree structure of postman data
	metadata := PostmanMetadata{
		WorkspaceId:   workspace.Id,
		WorkspaceName: workspace.Name,
		Type:          "workspace",
	}

	// gather and scan environment variables
	for _, environment_summary := range workspace.EnvironmentSummaries {
		if shouldSkip(environment_summary.Uid, s.conn.IncludeEnvironments, s.conn.ExcludeEnvironments) {
			continue
		}
		metadata.Type = ENVIRONMENT_TYPE
		metadata.Link = LINK_BASE_URL + "environments/" + environment_summary.Uid
		metadata.EnvironmentUid = environment_summary.Uid
		metadata.EnvironmentName = environment_summary.Name

		ctx.Logger().V(2).Info("scanning environment vars", "environment_uid", environment_summary.Uid)
		for _, word := range strings.Split(environment_summary.Name, " ") {
			s.attemptToAddKeyword(word)
		}
		metadata.LocationType = source_metadatapb.PostmanLocationType_ENVIRONMENT_VARIABLE

		environment, err := s.apiClient.GetEnvironmentByUid(ctx, environment_summary.Uid)
		if err != nil {
			ctx.Logger().Error(err, "could not get env variables", "environment_uid", environment_summary.Uid)
			continue
		}
		envVars := fp.Map(func(p struct{ Key, Value, SessionValue string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value, SessionValue: p.SessionValue}
		})(environment.KeyValues)
		s.scanVariableData(ctx, chunksChan, metadata, envVars)

		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
		metadata.Type = ""
		metadata.Link = ""
		metadata.EnvironmentUid = ""
		metadata.EnvironmentName = ""
		ctx.Logger().V(2).Info("finished scanning environment vars", "environment_uid", environment_summary.Uid)
	}
	ctx.Logger().V(2).Info("finished scanning environments")

	// scan all the collections in the workspace.
	// at this point we have all the possible
	// substitutions from Environment variables
	for _, collection_summary := range workspace.CollectionSummaries {
		if shouldSkip(collection_summary.Uid, s.conn.IncludeCollections, s.conn.ExcludeCollections) {
			continue
		}
		collection, err := s.apiClient.GetCollectionByUid(ctx, collection_summary.Uid)
		if err != nil {
			// Log and move on, because sometimes the Postman API seems to give us collection IDs
			// that we don't have access to, so we don't want to kill the scan because of it.
			ctx.Logger().Error(err, "error getting collection %s", collection_summary.Uid)
			continue
		}
		s.scanCollection(ctx, chunksChan, metadata, collection)
	}
	return nil
}

// scanCollection scans a collection and all its items, folders, and requests.
// locally scoped Metadata is updated as we drill down into the collection.
func (s *Source) scanCollection(ctx context.Context, chunksChan chan *sources.Chunk, metadata PostmanMetadata, collection PostmanCollection) {
	ctx.Logger().V(2).Info("starting to scan collection", "collection_name", collection.Name, "collection_uid", collection.Uid)
	metadata.CollectionName = collection.Name
	metadata.CollectionUid = collection.Uid
	metadata.Type = COLLECTION_TYPE
	s.attemptToAddKeyword(collection.Name)

	if !metadata.fromLocal {
		metadata.Link = LINK_BASE_URL + COLLECTION_TYPE + "/" + collection.Uid
	}

	metadata.LocationType = source_metadatapb.PostmanLocationType_COLLECTION_VARIABLE
	// environment variables must be scanned first before drilling down into the folders and events
	// because we need to pick up the substitutions from the top level collection variables
	variables := fp.Map(func(p struct{ Key, Value string }) VariableDatum {
		return VariableDatum{Key: p.Key, Value: p.Value}
	})(collection.Variables)
	s.scanVariableData(ctx, chunksChan, metadata, variables)
	metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN

	// collections don't have URLs in the Postman API, but we can scan the Authorization section without it.
	s.scanAuth(ctx, chunksChan, metadata, collection.Auth, PostmanCollectionUrl{})

	for _, event := range collection.Events {
		// Top level events don't have an Item ID (since they're at the top), so we just feed through an empty string)
		s.scanEvent(ctx, chunksChan, metadata, event, "")
	}

	for _, item := range collection.Items {
		s.scanItem(ctx, chunksChan, collection, metadata, item, "")
	}

}

// TODO - Confirm that all callers of this method are passing the parent UID _not_ the ID
func (s *Source) scanItem(ctx context.Context, chunksChan chan *sources.Chunk, collection PostmanCollection, metadata PostmanMetadata, item PostmanCollectionItem, parentItemUid string) {
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
		metadata.Link = LINK_BASE_URL + FOLDER_TYPE + "/" + item.Uid
	}
	// recurse through the folders
	for _, subItem := range item.Items {
		s.scanItem(ctx, chunksChan, collection, metadata, subItem, item.Uid)
	}

	// The assignment of the folder ID to be the current item UID is due to wanting to assume that your current item is a folder unless you have request data inside of your item.
	// If your current item is a folder, you will want the folder ID to match the UID of the current item.
	// If your current item is a request, you will want the folder ID to match the UID of the parent folder.
	// If the request is at the root of a collection and has no parent folder, the folder ID will be empty.
	metadata.FolderUid = item.Uid
	// check if there are any requests in the folder
	if item.Request.Method != "" {
		metadata.FolderName = strings.Replace(metadata.FolderName, (" > " + item.Name), "", -1)
		metadata.FolderUid = parentItemUid
		if metadata.FolderUid == "" {
			metadata.FolderName = ""
		}
		metadata.RequestUid = item.Uid
		metadata.RequestName = item.Name
		metadata.Type = REQUEST_TYPE
		if item.Uid != "" {
			// Route to API endpoint
			metadata.Link = LINK_BASE_URL + REQUEST_TYPE + "/" + item.Uid
		}
		s.scanHTTPRequest(ctx, chunksChan, metadata, item.Request)
	}

	// check if there are any responses in the folder
	for _, response := range item.Responses {
		s.scanHTTPResponse(ctx, chunksChan, metadata, response)
	}

	for _, event := range item.Events {
		s.scanEvent(ctx, chunksChan, metadata, event, item.Uid)
	}
	// an auth all by its lonesome could be inherited to subfolders and requests
	s.scanAuth(ctx, chunksChan, metadata, item.Auth, item.Request.Url)
	metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
}

func (s *Source) scanEvent(ctx context.Context, chunksChan chan *sources.Chunk, metadata PostmanMetadata, event PostmanCollectionEvent, itemId string) {
	metadata.Type = metadata.Type + " > event"
	data := strings.Join(event.Script.Exec, " ")

	// Prep direct links. Ignore updating link if it's a local JSON file
	if !metadata.fromLocal {
		metadata.Link = LINK_BASE_URL + (strings.Replace(metadata.Type, " > event", "", -1)) + "/" + itemId
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

	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, data)), metadata)
	metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
}

func (s *Source) scanAuth(ctx context.Context, chunksChan chan *sources.Chunk, m PostmanMetadata, auth PostmanCollectionAuth, url PostmanCollectionUrl) {
	var authData string
	switch auth.Type {
	case "apikey":
		var apiKeyValue, apiKeyName string
		for _, kv := range auth.ApiKey {
			switch kv.Key {
			case "key":
				apiKeyValue = fmt.Sprintf("%v", kv.Value)
			case "value":
				apiKeyName = fmt.Sprintf("%v", kv.Value)
			}
		}
		authData += fmt.Sprintf("%s=%s\n", apiKeyName, apiKeyValue)
	case "awsSigV4", "awsv4":
		for _, kv := range auth.AwsV4 {
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
		if url.Raw != "" {
			parsedURL, err := neturl.Parse(url.Raw)
			if err != nil {
				ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", url.Raw)
				return
			}

			parsedURL.User = neturl.User(username + ":" + password)
			decodedURL, err := neturl.PathUnescape(parsedURL.String())
			if err != nil {
				ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", url.Raw)
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
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(m, authData)), m)
	m.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
}

func (s *Source) scanHTTPRequest(ctx context.Context, chunksChan chan *sources.Chunk, metadata PostmanMetadata, request PostmanCollectionRequest) {
	s.addKeywords(request.Url.Host)
	originalType := metadata.Type

	// Add in var processing for headers
	if request.Headers != nil {
		vars := fp.Map(func(p struct{ Key, Value string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value}
		})(request.Headers)
		metadata.Type = originalType + " > header"
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_HEADER
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if request.Url.Raw != "" {
		metadata.Type = originalType + " > request URL (no query parameters)"
		// Note: query parameters are handled separately
		u := fmt.Sprintf("%s://%s/%s", request.Url.Protocol, strings.Join(request.Url.Host, "."), strings.Join(request.Url.Path, "/"))
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_URL
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, u)), metadata)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if len(request.Url.Query) > 0 {
		vars := fp.Map(func(p struct{ Key, Value string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value}
		})(request.Url.Query)
		metadata.Type = originalType + " > GET parameters (query)"
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_QUERY_PARAMETER
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if request.Auth.Type != "" {
		metadata.Type = originalType + " > request auth"
		s.scanAuth(ctx, chunksChan, metadata, request.Auth, request.Url)
	}

	if request.Body.Mode != "" {
		metadata.Type = originalType + " > body"
		s.scanRequestBody(ctx, chunksChan, metadata, request.Body)
	}
}

func (s *Source) scanRequestBody(ctx context.Context, chunksChan chan *sources.Chunk, metadata PostmanMetadata, body PostmanRequestBody) {
	if !metadata.fromLocal {
		metadata.Link = metadata.Link + "?tab=body"
	}
	originalType := metadata.Type
	switch body.Mode {
	case "formdata":
		metadata.Type = originalType + " > form data"
		vars := fp.Map(func(p struct{ Key, Value string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value}
		})(body.FormData)
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_FORM_DATA
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	case "urlencoded":
		metadata.Type = originalType + " > url encoded"
		vars := fp.Map(func(p struct{ Key, Value string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value}
		})(body.UrlEncoded)
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_URL_ENCODED
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	case "raw":
		metadata.Type = originalType + " > raw"
		data := body.Raw
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_RAW
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, data)), metadata)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	case "graphql":
		metadata.Type = originalType + " > graphql"
		data := body.GraphQl.Query + " " + body.GraphQl.Variables
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_BODY_GRAPHQL
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, data)), metadata)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}
}

func (s *Source) scanHTTPResponse(ctx context.Context, chunksChan chan *sources.Chunk, metadata PostmanMetadata, response PostmanCollectionResponse) {
	if response.Uid != "" {
		metadata.Link = LINK_BASE_URL + "example/" + response.Uid
	}
	originalType := metadata.Type

	if response.Headers != nil {
		vars := fp.Map(func(p struct{ Key, Value string }) VariableDatum {
			return VariableDatum{Key: p.Key, Value: p.Value}
		})(response.Headers)
		metadata.Type = originalType + " > response header"
		metadata.LocationType = source_metadatapb.PostmanLocationType_RESPONSE_HEADER
		s.scanVariableData(ctx, chunksChan, metadata, vars)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	// Body in a response is just a string
	if response.Body != "" {
		metadata.Type = originalType + " > response body"
		metadata.LocationType = source_metadatapb.PostmanLocationType_RESPONSE_BODY
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, response.Body)), metadata)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if response.OriginalRequest.Method != "" {
		metadata.Type = originalType + " > original request"
		s.scanHTTPRequest(ctx, chunksChan, metadata, response.OriginalRequest)
	}
}

func (s *Source) scanVariableData(ctx context.Context, chunksChan chan *sources.Chunk, metadata PostmanMetadata, variableData []VariableDatum) {
	if len(variableData) == 0 {
		ctx.Logger().V(2).Info("no variables to scan", "type", metadata.Type, "metadata", metadata)
		return
	}

	if !metadata.fromLocal && metadata.Type == COLLECTION_TYPE {
		metadata.Link += "?tab=variables"
	}

	values := []string{}
	for _, datum := range variableData {
		s.attemptToAddKeyword(datum.Key)
		valStr := fmt.Sprintf("%v", datum.Value)
		s.attemptToAddKeyword(valStr)
		if valStr != "" {
			s.sub.add(metadata, datum.Key, valStr)
		} else if datum.SessionValue != "" {
			valStr = fmt.Sprintf("%v", datum.SessionValue)
		}
		if valStr == "" {
			continue
		}
		values = append(values, s.buildSubstituteSet(metadata, valStr)...)
	}

	metadata.FieldType = metadata.Type + " variables"
	switch metadata.FieldType {
	case "request > GET parameters (query) variables":
		metadata.Link = metadata.Link + "?tab=params"
	case "request > header variables":
		metadata.Link = metadata.Link + "?tab=headers"
	}
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(values), metadata)
}

func (s *Source) scanData(ctx context.Context, chunksChan chan *sources.Chunk, data string, metadata PostmanMetadata) {
	if data == "" {
		ctx.Logger().V(3).Info("Data string is empty", "workspace_id", metadata.WorkspaceId)
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
					WorkspaceUuid:   metadata.WorkspaceId,
					WorkspaceName:   metadata.WorkspaceName,
					CollectionId:    metadata.CollectionUid,
					CollectionName:  metadata.CollectionName,
					EnvironmentId:   metadata.EnvironmentUid,
					EnvironmentName: metadata.EnvironmentName,
					RequestId:       metadata.RequestUid,
					RequestName:     metadata.RequestName,
					FolderId:        metadata.FolderUid,
					FolderName:      metadata.FolderName,
					FieldType:       metadata.FieldType,
					LocationType:    metadata.LocationType,
				},
			},
		},
		Verify: s.verify,
	}
}

func shouldSkip(identifier string, include []string, exclude []string) bool {
	if slices.Contains(exclude, identifier) {
		return true
	}
	if len(include) > 0 && !slices.Contains(include, identifier) {
		return true
	}
	return false
}
