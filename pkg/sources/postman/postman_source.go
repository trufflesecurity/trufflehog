package postman

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/repeale/fp-go"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	neturl "net/url"
	"strings"
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

type ChunkMetadata struct {
	WorkspaceId     string
	WorkspaceName   string
	CollectionId    string
	CollectionName  string
	EnvironmentId   string
	EnvironmentName string
	RequestId       string
	RequestName     string
	FolderId        string
	FolderName      string

	// These two are related, but not the same
	Type      string
	FieldType string

	LocationType source_metadatapb.PostmanLocationType
	Link         string // This is for the user, so they can go directly to the thing if a secret is found
}

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool

	// Mostly details about where and what to scan
	postmanSourceConfig *sourcespb.PostmanV2

	// Our api client
	postmanApiClient *postmanApiClient

	// Downstream from this logic the scanner uses thse keywords to match against detectors.  A better way might
	// be to put this information in the chunk itself (rather than keeping it here and resetting it for every
	// workspace), but that doesn't exist yet.
	DetectorKeywords map[string]struct{}

	// Keywords are words that are discovered when we walk through postman data.
	// These keywords are then injected into data that is sent to the detectors.
	keywords map[string]struct{}
	sub      *Substitution

	// We want to be able to set progress along the way
	sources.Progress
}

// Init
//
// Returns a fully initialized Postman source.
func (s *Source) Init(
	ctx context.Context,
	name string,
	jobId sources.JobID,
	sourceId sources.SourceID,
	verify bool,
	grpcMessage *anypb.Any,
	_ int,
) error {

	// Set up our basic fields
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.keywords = make(map[string]struct{})
	s.sub = NewSubstitution()

	// Grab the setup for this source from gRPC message that was passed in.
	var postmanSourceConfig sourcespb.PostmanV2
	if err := anypb.UnmarshalTo(grpcMessage, &postmanSourceConfig, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling Postman source config", 0)
	}
	s.postmanSourceConfig = &postmanSourceConfig

	// Get the Postman API key
	if postmanSourceConfig.GetToken() == "" {
		return errors.New("Postman token is empty")
	}
	s.postmanApiClient = NewPostmanApiClient(postmanSourceConfig.GetToken())

	return nil
}

// Type
//
// Returns the type of source. It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Chunks
//
// Scans the Postman source and sends the data to the chunks chan.
//
// The Postman source is different to our other sources in that we are not relying on the data we read from the source to contain
// all the information we need to scan, i.e, a git chunk contains all the information needed to check if a secret is present in that chunk.
// Postman on the other hand requires us to build context (the keywords and variables) as we scan the data.
// Check out the postman UI to see what I mean.
// Metadata is used to track information that informs the source of the chunk (e.g. the workspace -> collection -> request -> variable hierarchy).
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, targets ...sources.ChunkingTarget) error {

	// TODO - Extract this into something like "scanFromPostmanApi" so we can support other scan locations
	// Get the list of workspace IDs for the workspaces we need to scan
	workspaceIdsToScan, err := s.getWorkspaceIdsToScan(ctx)
	if err != nil {
		return fmt.Errorf("error getting workspace ids to scan: %v", err)
	}

	// Go through each workspace and scan it
	for _, workspaceId := range workspaceIdsToScan {
		s.SetProgressOngoing(fmt.Sprintf("Getting workspace with ID %s from Postman API", workspaceId), "")

		// First we grab the workspace from the Postman API
		workspace, err := s.postmanApiClient.GetWorkspaceById(ctx, workspaceId)
		if err != nil {
			// Log and move on, because sometimes the Postman API seems to give us workspace IDs
			// that we don't have access to, so we don't want to kill the scan because of it.
			ctx.Logger().Error(err, "error getting workspace %s", workspaceId)
			continue
		}
		s.SetProgressOngoing(fmt.Sprintf("Scanning workspace \"%s\" with id %s", workspace.Name, workspace.Id), "")
		s.scanWorkspace(ctx, chunksChan, workspace)
	}

	s.SetProgressComplete(1, 1, "Completed scanning Postman workspaces", "")
	return nil
}

// getWorkspaceIdsToScan
//
// # Returns a list of strings containing the workspaces IDs that we should be scanning
//
// There are two ways we can get a list of workspace IDs to scan:
//  1. During source configuration, the user provides a list of workspace IDs
//  2. We grab a list of all workspace IDs that are currently accessible to the provided
//     api key (which is tied to the user who generated it, incidentally)
//
// We only do 2 when the first option hasn't been provided.  The second path requires a
// call to the Postman API, while the first item doesn't. (We trust the user to have provided
// a good workspace ID)
func (s *Source) getWorkspaceIdsToScan(ctx context.Context) ([]string, error) {

	// If we already have some set of workspace IDs, just return those
	if s.postmanSourceConfig.WorkspaceIds != nil {
		ctx.Logger().V(4).Info("found the following workspace IDs in config: %v", s.postmanSourceConfig.WorkspaceIds)
		return s.postmanSourceConfig.WorkspaceIds, nil
	}

	// Otherwise we go directly to the postman API for this list
	workspaceSummaries, err := s.postmanApiClient.GetWorkspaceSummaryList(ctx)
	if err != nil {
		ctx.Logger().Error(err, "error getting workspace summary list from the postman client")
		return nil, err
	}
	workspaceIds := fp.Map(func(pws PostmanWorkspaceSummary) string { return pws.Id })(workspaceSummaries)
	ctx.Logger().V(4).Info("got workspace IDs accessible to the given API key: %d", len(workspaceIds))
	return workspaceIds, nil
}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspace PostmanWorkspace) error {
	// Prep keywords for downstream detector matching purposes
	s.resetDetectorKeywords()
	s.addDetectorKeyword(workspace.Name)

	// **************************************************************************************************************
	// Go through and get the environments/environment variables for each of the workspaces, then scan them
	for _, envSummary := range workspace.EnvironmentSummaries {

		// We have to go back to the API for each of these
		// TODO - Consider caching, since these might be share (likely are)
		environment, err := s.postmanApiClient.GetEnvironmentByUid(ctx, envSummary.Uid)
		if err != nil {
			// Log and move on - we don't want to kill the scan because of a single API error
			ctx.Logger().Error(err, "error getting environment \"%s\" with UID %s", envSummary.Name, envSummary.Uid)
			continue
		}

		// We add the name of the environment to the set of detector keywords.
		s.addDetectorKeywords(strings.Split(environment.Name, ""))

		// initiate metadata to track the tree structure of postman data
		metadata := ChunkMetadata{
			WorkspaceId:   workspace.Id,
			WorkspaceName: workspace.Name,
			Type:          "environment",
			LocationType:  source_metadatapb.PostmanLocationType_ENVIRONMENT_VARIABLE,
		}

		// This is where we do the actual scan
		s.scanEnvironment(ctx, chunksChan, environment, metadata)

	}

	// **************************************************************************************************************
	// Go through and get the Collections for each of the workspaces, then scan them
	for _, collectionSummary := range workspace.CollectionSummaries {

		collection, err := s.postmanApiClient.GetCollectionByUid(ctx, collectionSummary.Uid)
		if err != nil {
			// Log and move on - we don't want to kill the scan because of a single API error
			ctx.Logger().Error(err, "error getting collection \"%s\" with UID %s", collectionSummary.Name, collectionSummary.Uid)
			continue
		}

		// initiate metadata to track the tree structure of postman data
		metadata := ChunkMetadata{
			WorkspaceId:   workspace.Id,
			WorkspaceName: workspace.Name,
		}

		// This is where we do the actual scan
		s.scanCollection(ctx, chunksChan, collection, metadata)

	}

	return nil
}

func (s *Source) scanEnvironment(
	ctx context.Context,
	chunksChan chan *sources.Chunk,
	environment PostmanEnvironment,
	metadata ChunkMetadata,
) error {

	//  If there's nothing to scan, scan nothing
	if len(environment.KeyValues) == 0 {
		//ctx.Logger().V(2).Info("no variables to scan", "type", m.Type, "item_id", m.Id)
		return nil
	}

	// TODO Implement

	return nil
}

func (s *Source) scanCollection(
	ctx context.Context,
	chunksChan chan *sources.Chunk,
	collection PostmanCollection,
	metadata ChunkMetadata,
) error {
	ctx.Logger().V(2).Info("starting to scan collection", "collection_name", collection.Name, "collection_uid", collection.Uid)

	// Add in collection specific metadata
	metadata.Type = "collection"
	metadata.LocationType = source_metadatapb.PostmanLocationType_COLLECTION_VARIABLE

	// Add in our detector keywords
	s.addDetectorKeyword(collection.Name)

	return nil
}

// This is the bit where we actually pass off a chunk to the detectors
func (s *Source) buildAndSendChunkForDetection(ctx context.Context, chunksChan chan *sources.Chunk, data string, metadata ChunkMetadata) {
	// If there's no data, log and return
	if data == "" {
		ctx.Logger().V(3).Info("Data string is empty", "workspace_id", metadata.WorkspaceId)
		return
	}
	// TODO - Figure out if we can eliminate this
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
					CollectionId:    metadata.CollectionId,
					CollectionName:  metadata.CollectionName,
					EnvironmentId:   metadata.EnvironmentId,
					EnvironmentName: metadata.EnvironmentName,
					RequestId:       metadata.RequestId,
					RequestName:     metadata.RequestName,
					FolderId:        metadata.FolderId,
					FolderName:      metadata.FolderName,
					FieldType:       metadata.FieldType,
					LocationType:    metadata.LocationType,
				},
			},
		},
		Verify: s.verify,
	}
}

func (s *Source) scanAuth(ctx context.Context, chunksChan chan *sources.Chunk, metadata ChunkMetadata, auth PostmanAuth, url PostmanUrl) {
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

	s.addDetectorKeyword(authData)

	metadata.FieldType = AUTH_TYPE

	if strings.Contains(metadata.Type, REQUEST_TYPE) {
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_AUTHORIZATION
	} else if strings.Contains(metadata.Type, FOLDER_TYPE) {
		metadata.LocationType = source_metadatapb.PostmanLocationType_FOLDER_AUTHORIZATION
	} else if strings.Contains(metadata.Type, COLLECTION_TYPE) {
		metadata.LocationType = source_metadatapb.PostmanLocationType_COLLECTION_AUTHORIZATION
	}
	s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, authData)), metadata)
	metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
}

func (s *Source) scanHTTPRequest(ctx context.Context, chunksChan chan *sources.Chunk, metadata ChunkMetadata, request PostmanRequest) {
	s.addDetectorKeywords(request.Url.Host)
	originalType := metadata.Type

	// Add in var procesisng for headers
	if request.HeaderKeyValue != nil {
		vars := VariableData{
			KeyValues: request.HeaderKeyValue,
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
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, strings.Join(r.HeaderString, " "))), metadata)
		metadata.LocationType = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN
	}

	if r.URL.Raw != "" {
		metadata.Type = originalType + " > request URL (no query parameters)"
		// Note: query parameters are handled separately
		u := fmt.Sprintf("%s://%s/%s", r.URL.Protocol, strings.Join(r.URL.Host, "."), strings.Join(r.URL.Path, "/"))
		metadata.LocationType = source_metadatapb.PostmanLocationType_REQUEST_URL
		s.scanData(ctx, chunksChan, s.formatAndInjectKeywords(s.buildSubstituteSet(metadata, u)), metadata)
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

func (s *Source) addDetectorKeywords(keywords []string) {
	for _, keyword := range keywords {
		s.addDetectorKeyword(keyword)
	}
}

func (s *Source) addDetectorKeyword(keyword string) {
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

func (s *Source) resetDetectorKeywords() {
	s.keywords = make(map[string]struct{})
}
