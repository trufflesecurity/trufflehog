package postman

import (
	"fmt"
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

	// each collection has a set of variables (key-value pairs)
	// collectionVariables map[string]VariableData

	// each environment has a set of variables (key-value pairs)
	envVariables map[string]VariableData

	// ZRNOTE: Talk about this first but what about if we just gathered all the keywords and all the values
	// _then_ sent it on the chunks channel rather than trying to do on the fly bookkeeping?
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
	s.envVariables = make(map[string]VariableData)

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
	if s.conn.Workspaces != nil {
		for _, workspace := range s.conn.Workspaces {
			s.scanWorkspace(ctx, chunksChan, workspace)
		}
	}

	// Scan environments
	if s.conn.Environments != nil {
		// Need to validate these: technically these are not UUIDs but
		// <USER_ID>-<ENVIRONMENT_ID> where ENVIRONMENT_ID is a UUID.
		// Need to show in README how to generate these.
		var envs []IDNameUUID
		for _, environment := range s.conn.Environments {
			envs = append(envs, IDNameUUID{UUID: environment})
		}
		// Note that when we read in environment json files, there is no outer
		// environment field. Same for collections and outer collection field.
		s.scanEnvironments(ctx, chunksChan, Workspace{Environments: envs})
	}

	// Scan collections
	if s.conn.Collections != nil {
		var collections []IDNameUUID
		for _, collection := range s.conn.Collections {
			collections = append(collections, IDNameUUID{UUID: collection})
		}

		s.scanCollections(ctx, chunksChan, Workspace{Collections: collections})
	}

	// Scan personal workspaces (from API token)
	if s.conn.Workspaces == nil && s.conn.Collections == nil && s.conn.Environments == nil {
		workspaces, err := s.client.EnumerateWorkspaces()
		if err != nil {
			ctx.Logger().Error(errors.New("Could not enumerate any workspaces for the API token provided"), "failed to scan postman")
			return nil
		}
		for _, workspace := range workspaces {
			s.scanWorkspace(ctx, chunksChan, workspace.ID)
		}
	}

	return nil
}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspaceID string) {
	// reset keywords for each workspace
	s.keywords = []string{}

	w, err := s.client.GetWorkspace(workspaceID)
	if err != nil {
		s.log.Error(err, "could not get workspace object", "workspace_uuid", workspaceID)
	}
	s.keywords = append(s.keywords, w.Name)

	// scan global variables
	s.scanGlobals(ctx, chunksChan, w)

	// scan per environment variables
	s.scanEnvironments(ctx, chunksChan, w)

	// scan all the collections in the workspace.
	// at this point we have all the possible
	// substitutions from Global and Environment variables
	s.scanCollections(ctx, chunksChan, w)
}

func (s *Source) scanCollections(ctx context.Context, chunksChan chan *sources.Chunk, workspace Workspace) {
	ctx.Logger().V(2).Info("starting scanning collections")

	// Filter Collections
	collections := filterItemsByUUID(workspace.Collections, s.conn.ExcludeCollections, s.conn.IncludeCollections)

	// Scan Collections
	for _, col := range collections {
		collection, err := s.client.GetCollection(col.UUID)
		if err != nil {
			s.log.Error(err, "could not get collection object", "collection_uuid", col.UUID)
		}

		// metadata for the collection
		// we will populate this with item metadata as we scan through the collection's items
		metadata := Metadata{
			WorkspaceUUID:  workspace.ID,
			WorkspaceName:  workspace.Name,
			CreatedBy:      workspace.CreatedBy,
			CollectionInfo: collection.Info,
			Type:           COLLECTION_TYPE,
		}
		if metadata.CollectionInfo.UID != "" {
			// means we're reading in from an API call vs. local JSON file read
			metadata.FullID = metadata.CollectionInfo.UID
			metadata.Link = LINK_BASE_URL + COLLECTION_TYPE + "/" + metadata.FullID
		} else {
			// means we're reading in from a local JSON file
			metadata.FullID = metadata.CollectionInfo.PostmanID
			metadata.Link = "../" + metadata.FullID + ".json"
		}

		for _, item := range collection.Items {
			s.scanItem(ctx, chunksChan, collection, metadata, item)
		}

		// s.scanCollection(ctx, chunksChan, collection)
		// ZRNOTE: can we not just drill down into items, events, etc
	}
	ctx.Logger().V(2).Info("finished scanning collections")
}

func (s *Source) scanItem(ctx context.Context, chunksChan chan *sources.Chunk, collection Collection, metadata Metadata, item Item) {
	s.keywords = append(s.keywords, item.Name)

	// override the base collection metadata with item-specific metadata
	metadata.FolderID = item.ID
	metadata.Type = FOLDER_TYPE
	metadata.FolderName = item.Name
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

	s.scanHTTPItem(ctx, chunksChan, metadata, item)
	s.scanVariableData(ctx, chunksChan, metadata, VariableData{
		KeyValues: item.Variable,
	})
	s.scanEvents(ctx, chunksChan, metadata, item.Events)
	s.scanAuth(ctx, chunksChan, metadata, item.Auth, URL{})
}

func (s *Source) scanEvents(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, events []Event) {
	if events == nil {
		return
	}
	for _, event := range events {
		fmt.Println(event)
		// for _, subMap := range *varSubMap {
		// 	data := strings.Join(event.Script.Exec, " ")

		// 	// Prep direct links
		// 	link := LINK_BASE_URL + m.Type + "/" + m.FullID
		// 	if event.Listen == "prerequest" {
		// 		link += "?tab=pre-request-scripts"
		// 	} else {
		// 		link += "?tab=tests"
		// 	}

		// 	s.scanObject(ctx, chunksChan, Target{
		// 		Link:           link,
		// 		FieldType:      EVENT_TYPE,
		// 		FieldName:      event.Listen,
		// 		WorkspaceUUID:  m.WorkspaceUUID,
		// 		WorkspaceName:  m.WorkspaceName,
		// 		CollectionID:   m.CollectionInfo.PostmanID,
		// 		CollectionName: m.CollectionInfo.Name,
		// 		FolderName:     m.FolderName,
		// 		FolderId:       m.FolderID,
		// 		GlobalID:       m.FullID,
		// 		Data:           s.substitute(data, subMap),
		// 	})
		// }
	}
}

func (s *Source) substitute(data string, subMap map[string]string) string {
	// Question: with substitution, we're potentially alerting on every x item (ex: request auth field),
	// that the variable held in a folder "variable" field, when substituted in the request will reveal a secret.
	// Do users want to be alerted to every request that uses that secret or just the locatino of taht secret in the
	// folder "variable" field? The challenge is then keeping track of where taht substitution originated from. And we
	// have to use substitutions otherwise secrets won't have sufficient context to be tracked.
	// It's possible to keep track of the source of where the substitution originated from, but then we'd have to send many more individual scan objects.
	// Possible, but seems complex, but maybe a better user experience?
	for k, v := range subMap {
		k = "{{" + k + "}}"
		fmt.Println("SUBSTITUTING", k, "WITH", v)
		data = strings.ReplaceAll(data, k, v)
	}
	return data
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
	// case "oauth1":
	// 	s.scanAuthOAuth1(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	// case "digest":
	// 	s.scanAuthDigest(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	// case "hawk":
	// 	s.scanAuthHawk(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	// case "ntlm":
	// 	s.scanAuthNTLM(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	default:
		return
	}

	s.scanObject(ctx, chunksChan, Target{
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

func (s *Source) scanHTTPItem(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, item Item) {
	s.keywords = append(s.keywords, item.Name)
	// s.httpKeywords = append(s.httpKeywords, item.Name)
	// Adjust metadata here
	m.RequestID = item.ID
	m.RequestName = item.Name
	m.Type = REQUEST_TYPE
	// Adjust m.Type later on based on where in the request Ex: REQUEST (OriginalRequest Body)

	if item.UID != "" {
		// Route to API endpoint
		m.FullID = item.UID
		m.Link = LINK_BASE_URL + REQUEST_TYPE + "/" + item.UID
	} else {
		// Route to collection.json
		m.FullID = item.ID
		m.Link = "../" + m.CollectionInfo.PostmanID + ".json"
	}

	if item.Events != nil {
		m.Type = m.Type + " > event"
		s.scanEvents(ctx, chunksChan, m, item.Events)
	}
	if item.Request.Method != "" {
		s.scanHTTPRequest(ctx, chunksChan, m, item.Request)
	}
	if len(item.Response) > 0 {
		s.scanHTTPResponse(ctx, chunksChan, m, item.Response)
	}
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
		// for _, subMap := range *varSubMap {
		// 	data += s.substitute(data, subMap)
		// }
		s.scanObject(ctx, chunksChan, Target{
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

	if len(r.URL.Host) > 0 {
		for _, host := range r.URL.Host {
			s.keywords = append(s.keywords, host)
			// s.httpKeywords = append(s.httpKeywords, host)

			// for _, subMap := range *varSubMap {
			// 	s.keywords = append(s.keywords, s.substitute(host, subMap))
			// 	// s.httpKeywords = append(s.httpKeywords, s.substitute(host, subMap))
			// }
		}
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
	case "raw":
		m.Type = m.Type + " > raw"
		data := b.Raw
		// for _, subMap := range *varSubMap {
		// 	data += s.substitute(data, subMap)
		// }
		s.scanObject(ctx, chunksChan, Target{
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
	case "graphql":
		m.Type = m.Type + " > graphql"
		data := b.GraphQL.Query + " " + b.GraphQL.Variables
		// for _, subMap := range *varSubMap {
		// 	data += s.substitute(data, subMap)
		// }
		s.scanObject(ctx, chunksChan, Target{
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

func (s *Source) scanHTTPResponse(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, r []Response) {
	for _, response := range r {

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
			s.scanObject(ctx, chunksChan, Target{
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
}

func (s *Source) scanGlobals(ctx context.Context, chunksChan chan *sources.Chunk, w Workspace) {
	ctx.Logger().V(2).Info("starting scanning global variables")
	globalVars, err := s.client.GetGlobalVariables(w.ID)
	if err != nil {
		s.log.Error(err, "could not get global variables object")
	}

	// Will need to adjust FullID and Link for local JSON read in
	m := Metadata{
		WorkspaceUUID: w.ID,
		WorkspaceName: w.Name,
		CreatedBy:     w.CreatedBy,
		Type:          GLOBAL_TYPE,
		FullID:        w.CreatedBy + "-" + globalVars.ID,
		Link:          LINK_BASE_URL + "workspace/" + w.ID + "/" + GLOBAL_TYPE,
	}

	s.scanVariableData(ctx, chunksChan, m, globalVars)
	ctx.Logger().V(2).Info("finished scanning global variables")
}

func (s *Source) scanEnvironments(ctx context.Context, chunksChan chan *sources.Chunk, w Workspace) {
	ctx.Logger().V(2).Info("starting scanning environments")

	// Filter Enviroments
	environments := filterItemsByUUID(w.Environments, s.conn.ExcludeEnvironments, s.conn.IncludeEnvironments)

	// Scan Environments
	for _, env := range environments {
		envVars, err := s.client.GetEnvironment(env.UUID)
		if err != nil {
			s.log.Error(err, "could not get environment object", "environment_uuid", env.UUID)
		}
		// Will need to adjust FullID and Link for local JSON read in
		m := Metadata{
			WorkspaceUUID: w.ID,
			WorkspaceName: w.Name,
			CreatedBy:     w.CreatedBy,
			Type:          ENVIRONMENT_TYPE,
			FullID:        env.UUID,
			Link:          LINK_BASE_URL + ENVIRONMENT_TYPE + "/" + env.UUID,
		}
		// scan environment
		vars := envVars.VariableData
		ctx.Logger().V(2).Info("scanning environment vars", "environment_uuid", m.FullID)
		for _, word := range strings.Split(vars.Name, " ") {
			s.keywords = append(s.keywords, string(word))
			// s.environmentKeywords = append(s.environmentKeywords, string(word))
		}

		s.scanVariableData(ctx, chunksChan, m, vars)
		ctx.Logger().V(2).Info("finished scanning environment vars", "environment_uuid", m.FullID)
	}
	ctx.Logger().V(2).Info("finished scanning environments")
}

func (s *Source) scanVariableData(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, variableData VariableData) {
	if variableData.KeyValues == nil {
		ctx.Logger().V(2).Info("no variables to scan", "type", m.Type, "uuid", m.FullID)
		return
	}

	// If collection and not a JSON file, then append the tab=variables to the link
	if m.Type == COLLECTION_TYPE {
		if !strings.HasSuffix(m.Link, ".json") {
			m.Link += "?tab=variables"
		}
	}

	// Question: Despite lots of efforts to avoid duplicates, they'll still exist.
	// Is there a way to adjust the scanning mechanism so that for only Postman
	// we avoid duplicates? It's kind of just the nature of dealing with
	// user-generated key-value pairs.

	//Pre-process each key=var pair
	// 1. Map key=value pairs for substitution later in workspace processing
	// 2. Create slice of strings (keys and values) for use in processing variables
	// ex: API_KEY=<AN_OPENWEATHERMAP_API_KEY>, then there is a URI=https://openweathermap.com
	//     or another key is OPENWEATHER_ID={{no_data}}; either way we need both keys and values
	//     within 40 chars of the API Key.
	// 3. Create a value string of all values.
	//    We need to append all of these values for secrets that need a second cred. Like AWS or Shopify URLs.
	//    But we don't want one value to trigger another value in the wrong var, so pad with 50 spaces.

	//
	// ZRNOTE: i don't know if 3. works as intended. For most multipart cred we also need an identifier
	// associated with the secret
	//

	// varSubstitutions := map[string]string{}

	// This loop gathers all the postman variables in a workspace or collection
	// The keys are added to the on going list of keywords
	// The values will be injected with keywords to be scanned as objects later
	values := []string{}
	for _, v := range variableData.KeyValues {
		s.keywords = append(s.keywords, v.Key)
		values = append(values, fmt.Sprintf("%v", v.Value))

		if v.SessionValue != "" {
			sessionValue := fmt.Sprintf("%v", v.SessionValue)
			s.keywords = append(s.keywords, sessionValue)
			values = append(values, sessionValue)
		}
	}

	// Filter out keywords that don't exist in pkg/detectors/*
	filteredKeywords := filterKeywords(s.keywords, s.detectorKeywords)
	if len(filteredKeywords) == 0 {
		return
	}

	for _, keyword := range filteredKeywords {
		data := ""
		for _, value := range values {
			data += fmt.Sprintf("%s:%s\n ", keyword, value)
		}
	}

	allValues := strings.Join(values, strings.Repeat(" ", KEYWORD_PADDING)+"\n")
	// allValues := " "
	// for _, value := range values {
	// 	allValues += (+value)
	// }

	// Create slice of objects to scan (both context & data)
	pmObjToScan := []Target{}
	for _, v := range variableData.KeyValues {
		data := fmt.Sprintf("%s:%s ", v.Key, fmt.Sprintf("%v", v.Value))
		for _, keyword := range filteredKeywords {
			if keyword == fmt.Sprintf("%v", v.Value) {
				continue
			}
			data += fmt.Sprintf("%s:%s ", keyword, fmt.Sprintf("%v", v.Value))
			data += strings.Repeat(" ", KEYWORD_PADDING)
		}
		data += allValues
		preScanObj := Target{
			Link:           m.Link,
			WorkspaceUUID:  m.WorkspaceUUID,
			WorkspaceName:  m.WorkspaceName,
			CollectionID:   m.CollectionInfo.PostmanID,
			CollectionName: m.CollectionInfo.Name,
			GlobalID:       m.FullID,
			FieldType:      m.Type + " variable",
			FieldName:      v.Key,
			VarType:        v.Type,
			Data:           data,
		}
		pmObjToScan = append(pmObjToScan, preScanObj)
		// This is a legacy field from Postman. But they can still exist (although invisible in UI).
		if v.SessionValue != "" {
			var data string
			for _, keyword := range filteredKeywords {
				if keyword == fmt.Sprintf("%v", v.SessionValue) {
					continue
				}
				data += fmt.Sprintf("%s:%v\n", keyword, v.SessionValue)
				data += strings.Repeat(" ", KEYWORD_PADDING)
			}
			data += allValues
			preScanObj.Data = data
			preScanObj.VarType = "Session Value (hidden from UI)"
			pmObjToScan = append(pmObjToScan, preScanObj)
		}
	}

	// If no keys match keywords, it's possible we'll end up with  multiple objects all containing the same
	// string, which would just be the values of all variables. We only need to process one, but we can't be sure
	// which variable is at fault, so for those objects, we'll "" the FieldName. Then we'll remove duplicates.
	// This is a bit of a hack, but it's the best we can do without a better way to identify the variable.

	var dataCount = make(map[string]int)

	for _, obj := range pmObjToScan {
		dataCount[obj.Data]++
	}
	for i, obj := range pmObjToScan {
		if dataCount[obj.Data] > 1 {
			pmObjToScan[i].FieldName = ""
		}
	}

	// Add to slice of maps for substitution later
	// if varSubMap == nil {
	// 	varSubMap = &[]map[string]string{}
	// }
	// fmt.Println("[scan vars] varSubMap", varSubMap)
	// *varSubMap = append(*varSubMap, varSubstitutions)
	s.scanObjects(ctx, chunksChan, pmObjToScan)
}

func (s *Source) scanObjects(ctx context.Context, chunksChan chan *sources.Chunk, objects []Target) {
	//Remove duplicate objects to scan
	uniqueMap := make(map[Target]struct{})
	uniqueObjects := []Target{}

	// Iterate through the input slice and add unique objects to the map
	for _, obj := range objects {
		if _, exists := uniqueMap[obj]; !exists {
			uniqueMap[obj] = struct{}{}
			uniqueObjects = append(uniqueObjects, obj)
		}
	}

	// Process each object.
	done := make(chan struct{})

	// Process each object concurrently.
	for _, obj := range uniqueObjects {
		go func(obj Target) {
			defer func() {
				done <- struct{}{} // Signal that the goroutine has completed.
			}()
			s.scanObject(ctx, chunksChan, obj)
		}(obj)
	}

	// Wait for all goroutines to finish.
	for range uniqueObjects {
		<-done
	}
}

func (s *Source) scanObject(ctx context.Context, chunksChan chan *sources.Chunk, o Target) {
	fmt.Println("#########START OBJECT#########")
	fmt.Println(o.Data + "\n")
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
		containsDetector := false
		lowerKey := strings.ToLower(key)
		for detectorKey := range detectorKeywords {
			if strings.Contains(lowerKey, detectorKey) {
				containsDetector = true
				break
			}
		}
		if containsDetector {
			filteredKeywords[key] = struct{}{}
		}
	}

	// Remove duplicates, but these are defined as situations like this:
	// openweathermap.com, openweather and api.openweathermap.com
	// In this scenario only openweather needs to remain

	// Update this to return []string.

	var uniqueKeywords []string

	// Iterate through the filtered keywords
	for name := range filteredKeywords {
		foundSimilar := false
		lowerName := strings.ToLower(name)
		// Check if the name is similar to any of the unique canonical names
		for _, key := range uniqueKeywords {
			lowerKey := strings.ToLower(key)
			if strings.Contains(lowerKey, lowerName) || strings.Contains(lowerName, lowerKey) {
				// A similar name is found, skip adding it to the map
				foundSimilar = true
				break
			}
		}

		if !foundSimilar {
			// No similar name found, add it to the map
			uniqueKeywords = append(uniqueKeywords, name)
		}
	}

	return uniqueKeywords
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
