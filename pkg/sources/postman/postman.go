package postman

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
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
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	concurrency int
	log         logr.Logger
	sources.Progress
	jobPool *errgroup.Group
	client  *Client
	conn    *sourcespb.Postman
	sources.CommonSourceUnitUnmarshaller
	detectorKeywords map[string]struct{}
}

type PMScanObject struct {
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

type ArchiveJSON struct {
	Collection  map[string]bool `json:"collection"`
	Environment map[string]bool `json:"environment"`
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// ToDo:
// 2. Read in local JSON files
// 3. Add tests
// 4. Try to filter out duplicate objects

// func verifyPostmanExportZip(filepath string) ArchiveJSON {
// 	var archiveData ArchiveJSON

// 	// Open the ZIP archive.
// 	r, err := zip.OpenReader(filepath)
// 	if err != nil {
// 		fmt.Println("Error opening ZIP file:", err)
// 		return archiveData
// 	}
// 	defer r.Close()

// 	// Iterate through the files in the ZIP archive.
// 	for _, file := range r.File {
// 		if strings.HasSuffix(file.Name, "archive.json") {
// 			// Open the file within the ZIP archive.
// 			rc, err := file.Open()
// 			if err != nil {
// 				fmt.Println("Error opening archive.json:", err)
// 				return archiveData
// 			}
// 			defer rc.Close()

// 			// Read the contents of archive.json.
// 			contents, err := io.ReadAll(rc)
// 			if err != nil {
// 				fmt.Println("Error reading archive.json:", err)
// 				return archiveData
// 			}

// 			// Unmarshal the JSON contents into the ArchiveJSON struct.
// 			if err := json.Unmarshal(contents, &archiveData); err != nil {
// 				fmt.Println("Error decoding JSON:", err)
// 				return archiveData
// 			}

// 			// Check if the structure matches your requirements.
// 			return archiveData
// 		}
// 	}
// 	return archiveData
// }

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

	var conn sourcespb.Postman
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.conn = &conn

	keywords := make(map[string]struct{})
	for _, key := range s.conn.DetectorKeywords {
		keywords[key] = struct{}{}
	}
	s.detectorKeywords = keywords

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
	if s.conn.Workspaces != nil {
		for _, workspace := range s.conn.Workspaces {
			s.scanWorkspace(ctx, chunksChan, workspace)
		}
	}
	if s.conn.Environments != nil {
		// Need to validate these: technically these are not UUIDs but
		// <USER_ID>-<ENVIRONMENT_ID> where ENVIRONMENT_ID is a UUID.
		// Need to show in README how to generate these.
		var envs []IDNameUUID
		for _, environment := range s.conn.Environments {
			envs = append(envs, IDNameUUID{UUID: environment})
		}
		w := WorkspaceObj{
			Workspace: WorkspaceStruct{
				Environments: envs,
			},
		}
		s.scanEnvironments(ctx, chunksChan, w, nil, nil)
		// Note that when we read in environment json files, there is no outer
		// environment field. Same for collections and outer collection field.
	}
	if s.conn.Collections != nil {
		var colls []IDNameUUID
		for _, collection := range s.conn.Collections {
			colls = append(colls, IDNameUUID{UUID: collection})
		}
		w := WorkspaceObj{
			Workspace: WorkspaceStruct{
				Collections: colls,
			},
		}
		var varSubMap []map[string]string
		varSubMap = append(varSubMap, make(map[string]string)) //include an empty varsubmap for the substitution function
		s.scanCollections(ctx, chunksChan, w, nil, &varSubMap)
	}
	if s.conn.Workspaces == nil && s.conn.Collections == nil && s.conn.Environments == nil {
		workspaces, err := s.client.EnumerateWorkspaces()
		if err != nil {
			ctx.Logger().Error(errors.New("Could not enumerate any workspaces for the API token provided"), "failed to scan postman")
			return nil
		}
		for _, workspace := range workspaces.Workspaces {
			s.scanWorkspace(ctx, chunksChan, workspace.ID)
		}
	}

	return nil
}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, workspaceID string) {
	var varSubMap []map[string]string
	varSubMap = append(varSubMap, make(map[string]string)) //include an empty varsubmap for the substitution function
	w, err := s.client.GetWorkspace(workspaceID)
	if err != nil {
		s.log.Error(err, "could not get workspace object", "workspace_uuid", workspaceID)
	}
	var extraKeywords []string
	extraKeywords = append(extraKeywords, w.Workspace.Name)
	s.scanGlobals(ctx, chunksChan, w, extraKeywords, &varSubMap)
	s.scanEnvironments(ctx, chunksChan, w, extraKeywords, &varSubMap)
	s.scanCollections(ctx, chunksChan, w, extraKeywords, &varSubMap)
}

func (s *Source) scanCollections(ctx context.Context, chunksChan chan *sources.Chunk, w WorkspaceObj, extraKeywords []string, varSubMap *[]map[string]string) {
	ctx.Logger().V(2).Info("starting scanning collections")

	// Filter Collections
	collections := filterItemsByUUID(w.Workspace.Collections, s.conn.ExcludeCollections, s.conn.IncludeCollections)

	// Scan Collections
	for _, col := range collections {
		c, err := s.client.GetCollection(col.UUID)
		if err != nil {
			s.log.Error(err, "could not get collection object", "collection_uuid", col.UUID)
		}
		m := Metadata{
			WorkspaceUUID:  w.Workspace.ID,
			WorkspaceName:  w.Workspace.Name,
			CreatedBy:      w.Workspace.CreatedBy,
			CollectionInfo: c.Collection.Info,
			Type:           COLLECTION_TYPE,
		}
		if m.CollectionInfo.UID != "" {
			// means we're reading in from an API call vs. local JSON file read
			m.FullID = m.CollectionInfo.UID
			m.Link = LINK_BASE_URL + COLLECTION_TYPE + "/" + m.FullID
		} else {
			// means we're reading in from a local JSON file
			m.FullID = m.CollectionInfo.PostmanID
			m.Link = "../" + m.FullID + ".json"
		}
		s.scanCollection(ctx, chunksChan, m, c.Collection, extraKeywords, varSubMap)
	}
	ctx.Logger().V(2).Info("finished scanning collections")
}

func (s *Source) scanCollection(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, c Collection, extraKeywords []string, varSubMap *[]map[string]string) {
	// Deep copy varSubMap
	varSubMapCopy := make([]map[string]string, len(*varSubMap))
	for i, originalMap := range *varSubMap {
		newMap := make(map[string]string)
		for k, v := range originalMap {
			newMap[k] = v
		}
		varSubMapCopy[i] = newMap
	}
	s.scanFolderMetadata(ctx, chunksChan, m, c.Variable, c.Event, c.Auth, extraKeywords, &varSubMapCopy)
	s.scanFolder(ctx, chunksChan, m, c.Item, extraKeywords, &varSubMapCopy)
}

// Scan non-item fields in folder. Outer most folder is a collection.
func (s *Source) scanFolderMetadata(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, vars []KeyValue, e []Event, a Auth, extraKeywords []string, varSubMap *[]map[string]string) {
	varData := VariableData{
		KeyValues: vars,
	}
	s.scanVars(ctx, chunksChan, m, varData, extraKeywords, varSubMap)
	s.scanEvents(ctx, chunksChan, m, e, varSubMap)
	s.scanAuth(ctx, chunksChan, m, a, URL{}, extraKeywords, varSubMap)
}

func (s *Source) scanEvents(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, events []Event, varSubMap *[]map[string]string) {
	if events == nil {
		return
	}
	for _, event := range events {
		for _, subMap := range *varSubMap {
			data := strings.Join(event.Script.Exec, " ")

			// Prep direct links
			link := LINK_BASE_URL + m.Type + "/" + m.FullID
			if event.Listen == "prerequest" {
				link += "?tab=pre-request-scripts"
			} else {
				link += "?tab=tests"
			}

			s.scanObject(ctx, chunksChan, PMScanObject{
				Link:           link,
				FieldType:      EVENT_TYPE,
				FieldName:      event.Listen,
				WorkspaceUUID:  m.WorkspaceUUID,
				WorkspaceName:  m.WorkspaceName,
				CollectionID:   m.CollectionInfo.PostmanID,
				CollectionName: m.CollectionInfo.Name,
				FolderName:     m.FolderName,
				FolderId:       m.FolderID,
				GlobalID:       m.FullID,
				Data:           s.substitute(data, subMap),
			})
		}
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
		data = strings.ReplaceAll(data, k, v)
	}
	return data
}

// Process Auth
// Create scanHTTPItem function

func (s *Source) parseAPIKey(ctx context.Context, a Auth, extraKeywords []string, varSubMap *[]map[string]string) string {
	if len(a.Apikey) == 0 {
		return ""
	}
	var data string
	var apiKeyValue string
	var apiKeyName string
	for _, kv := range a.Apikey {
		switch kv.Key {
		case "key":
			apiKeyValue = fmt.Sprintf("%v", kv.Value)
		case "value":
			apiKeyName = fmt.Sprintf("%v", kv.Value)
		}
	}
	data += fmt.Sprintf("%s=%s\n", apiKeyName, apiKeyValue)
	for _, keyword := range extraKeywords {
		data += fmt.Sprintf("%s:%s ", keyword, apiKeyValue)
	}
	for _, subMap := range *varSubMap {
		// Substitute for both key and value, for both regular and keyword subbed in
		data += s.substitute(data, subMap)
	}
	return data
}

func (s *Source) parseAWSAuth(ctx context.Context, a Auth, varSubMap *[]map[string]string) string {
	if len(a.AWSv4) == 0 {
		return ""
	}
	var data string
	var awsAccessKey string
	var awsSecretKey string
	var awsRegion string
	var awsService string
	for _, kv := range a.AWSv4 {
		switch kv.Key {
		case "accessKey":
			awsAccessKey = fmt.Sprintf("%v", kv.Value)
		case "secretKey":
			awsSecretKey = fmt.Sprintf("%v", kv.Value)
		case "region":
			awsRegion = fmt.Sprintf("%v", kv.Value)
		case "service":
			awsService = fmt.Sprintf("%v", kv.Value)
		}
	}
	data += fmt.Sprintf("accessKey:%s secretKey:%s region:%s service:%s\n", awsAccessKey, awsSecretKey, awsRegion, awsService)
	for _, subMap := range *varSubMap {
		data += s.substitute(data, subMap)
	}
	return data
}

func (s *Source) parseBearer(ctx context.Context, a Auth, extraKeywords []string, varSubMap *[]map[string]string) string {
	if len(a.Bearer) == 0 {
		return ""
	}
	var data string
	var bearerKey string
	var bearerValue string
	for _, kv := range a.Bearer {
		bearerValue = fmt.Sprintf("%v", kv.Value)
		bearerKey = fmt.Sprintf("%v", kv.Key)
	}
	data += fmt.Sprintf("%s:%s\n", bearerKey, bearerValue)
	for _, keyword := range extraKeywords {
		data += fmt.Sprintf("%s:%s ", keyword, bearerValue)
	}
	for _, subMap := range *varSubMap {
		// Substitute for both key and value, for both regular and keyword subbed in
		data += s.substitute(data, subMap)
	}
	return data
}

func (s *Source) parseBasicAuth(ctx context.Context, a Auth, u URL, extraKeywords []string, varSubMap *[]map[string]string) string {
	if len(a.Basic) == 0 {
		return ""
	}
	var data string
	var basicUsername string
	var basicPassword string
	for _, kv := range a.Basic {
		switch kv.Key {
		case "username":
			basicUsername = fmt.Sprintf("%v", kv.Value)
		case "password":
			basicPassword = fmt.Sprintf("%v", kv.Value)
		}
	}
	data += fmt.Sprintf("username:%s password:%s ", basicUsername, basicPassword)
	for _, keyword := range extraKeywords {
		data += fmt.Sprintf("%s:%s ", keyword, basicPassword)
	}

	if u.Raw != "" {
		// Question: Do we still need keywords located near https://username:password@domain?
		parsedURL, err := url.Parse(u.Raw)
		if err != nil {
			ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
			return data
		}

		parsedURL.User = url.User(basicUsername + ":" + basicPassword)
		decodedURL, err := url.PathUnescape(parsedURL.String())
		if err != nil {
			ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
			return data
		}
		data += (decodedURL + " ")
	}

	for _, subMap := range *varSubMap {
		data += s.substitute(data, subMap)
	}

	return data
}

func (s *Source) parseOAuth2(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, a Auth, extraKeywords []string, varSubMap *[]map[string]string) string {
	if len(a.OAuth2) == 0 {
		return ""
	}
	var data string
	for _, oauth := range a.OAuth2 {
		switch oauth.Key {
		case "accessToken", "refreshToken", "clientId", "clientSecret", "accessTokenUrl", "authUrl":
			data += fmt.Sprintf("%s:%v ", oauth.Key, oauth.Value)
			for _, keyword := range extraKeywords {
				data += fmt.Sprintf("%s:%v ", keyword, oauth.Value)
			}
		}
	}
	for _, subMap := range *varSubMap {
		data += s.substitute(data, subMap)
	}
	return data
}

func (s *Source) scanAuth(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, a Auth, u URL, extraKeywords []string, varSubMap *[]map[string]string) {
	if a.Type == "" {
		return
	}
	var authData string
	switch a.Type {
	case "apikey":
		authData = s.parseAPIKey(ctx, a, extraKeywords, varSubMap)
	case "awsSigV4":
		authData = s.parseAWSAuth(ctx, a, varSubMap)
	case "bearer":
		authData = s.parseBearer(ctx, a, extraKeywords, varSubMap)
	case "basic":
		authData = s.parseBasicAuth(ctx, a, u, extraKeywords, varSubMap)
	// case "digest":
	// 	s.scanAuthDigest(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	// case "hawk":
	// 	s.scanAuthHawk(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	case "noauth":
		authData = ""
	// case "oauth1":
	// 	s.scanAuthOAuth1(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	case "oauth2":
		authData = s.parseOAuth2(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	// case "ntlm":
	// 	s.scanAuthNTLM(ctx, chunksChan, m, a, extraKeywords, varSubMap)
	default:
		authData = ""
	}

	s.scanObject(ctx, chunksChan, PMScanObject{
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

func (s *Source) scanFolder(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, FolderData []Item, extraKeywords []string, varSubMap *[]map[string]string) {
	for _, folder := range FolderData {
		extraKeywords = append(extraKeywords, folder.Name)

		// Adjust metadata here
		m.FolderID = folder.ID
		m.Type = FOLDER_TYPE
		m.FolderName = folder.Name
		if folder.UID != "" {
			m.FullID = folder.UID
			m.Link = LINK_BASE_URL + FOLDER_TYPE + "/" + m.FullID
		} else {
			m.FullID = folder.ID
			m.Link = "../" + m.FullID + ".json"
		}

		if folder.Item != nil {
			s.scanFolderMetadata(ctx, chunksChan, m, nil, folder.Event, folder.Auth, extraKeywords, varSubMap)
			s.scanFolder(ctx, chunksChan, m, folder.Item, extraKeywords, varSubMap)
		} else {
			s.scanHTTPItem(ctx, chunksChan, m, folder, extraKeywords, varSubMap)
		}
	}
}

func (s *Source) scanHTTPItem(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, item Item, extraKeywords []string, varSubMap *[]map[string]string) {
	extraKeywords = append(extraKeywords, item.Name)
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

	if item.Event != nil {
		m.Type = m.Type + " > event"
		s.scanEvents(ctx, chunksChan, m, item.Event, varSubMap)
	}
	if item.Request.Method != "" {
		s.scanHTTPRequest(ctx, chunksChan, m, item.Request, extraKeywords, varSubMap)
	}
	if len(item.Response) > 0 {
		s.scanHTTPResponse(ctx, chunksChan, m, item.Response, extraKeywords, varSubMap)
	}
}

func (s *Source) scanHTTPRequest(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, r Request, extraKeywords []string, varSubMap *[]map[string]string) {
	// Add in var procesisng for headers
	if r.Header != nil {
		vars := VariableData{
			KeyValues: r.Header,
		}
		m.Type = m.Type + " > header"
		s.scanVars(ctx, chunksChan, m, vars, extraKeywords, varSubMap)
	}

	if r.URL.Raw != "" {
		m.Type = m.Type + " > request URL"
		data := r.URL.Raw
		for _, subMap := range *varSubMap {
			data += s.substitute(data, subMap)
		}
		s.scanObject(ctx, chunksChan, PMScanObject{
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
	}

	if len(r.URL.Host) > 0 {
		for _, host := range r.URL.Host {
			extraKeywords = append(extraKeywords, host)
			for _, subMap := range *varSubMap {
				extraKeywords = append(extraKeywords, s.substitute(host, subMap))
			}
		}
	}

	if len(r.URL.Query) > 0 {
		vars := VariableData{
			KeyValues: r.URL.Query,
		}
		m.Type = m.Type + " > GET parameters (query)"
		s.scanVars(ctx, chunksChan, m, vars, extraKeywords, varSubMap)
	}

	if r.Auth.Type != "" {
		m.Type = m.Type + " > request auth"
		s.scanAuth(ctx, chunksChan, m, r.Auth, URL{}, extraKeywords, varSubMap)
	}

	if r.Body.Mode != "" {
		m.Type = m.Type + " > body"
		s.scanBody(ctx, chunksChan, m, r.Body, extraKeywords, varSubMap)
	}
}

func (s *Source) scanBody(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, b Body, extraKeywords []string, varSubMap *[]map[string]string) {
	m.Link = m.Link + "?tab=body"
	switch b.Mode {
	case "formdata":
		m.Type = m.Type + " > form data"
		vars := VariableData{
			KeyValues: b.FormData,
		}
		s.scanVars(ctx, chunksChan, m, vars, extraKeywords, varSubMap)
	case "urlencoded":
		m.Type = m.Type + " > url encoded"
		vars := VariableData{
			KeyValues: b.URLEncoded,
		}
		s.scanVars(ctx, chunksChan, m, vars, extraKeywords, varSubMap)
	case "raw":
		m.Type = m.Type + " > raw"
		data := b.Raw
		for _, subMap := range *varSubMap {
			data += s.substitute(data, subMap)
		}
		s.scanObject(ctx, chunksChan, PMScanObject{
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
		for _, subMap := range *varSubMap {
			data += s.substitute(data, subMap)
		}
		s.scanObject(ctx, chunksChan, PMScanObject{
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

func (s *Source) scanHTTPResponse(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, r []Response, extraKeywords []string, varSubMap *[]map[string]string) {
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
			s.scanVars(ctx, chunksChan, m, vars, extraKeywords, varSubMap)
		}

		// Body in a response is just a string
		if response.Body != "" {
			m.Type = m.Type + " > response body"
			s.scanObject(ctx, chunksChan, PMScanObject{
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
			s.scanHTTPRequest(ctx, chunksChan, m, response.OriginalRequest, extraKeywords, varSubMap)
		}
	}
}

func (s *Source) scanGlobals(ctx context.Context, chunksChan chan *sources.Chunk, w WorkspaceObj, extraKeywords []string, varSubMap *[]map[string]string) {
	ctx.Logger().V(2).Info("starting scanning global variables")
	globalVars, err := s.client.GetGlobals(w.Workspace.ID)
	if err != nil {
		s.log.Error(err, "could not get global variables object")
	}

	// Will need to adjust FullID and Link for local JSON read in
	m := Metadata{
		WorkspaceUUID: w.Workspace.ID,
		WorkspaceName: w.Workspace.Name,
		CreatedBy:     w.Workspace.CreatedBy,
		Type:          GLOBAL_TYPE,
		FullID:        w.Workspace.CreatedBy + "-" + globalVars.ID,
		Link:          LINK_BASE_URL + "workspace/" + w.Workspace.ID + "/" + GLOBAL_TYPE,
	}

	s.scanVars(ctx, chunksChan, m, globalVars.VariableData, extraKeywords, varSubMap)
	ctx.Logger().V(2).Info("finished scanning global variables")
}

func (s *Source) scanEnvironments(ctx context.Context, chunksChan chan *sources.Chunk, w WorkspaceObj, extraKeywords []string, varSubMap *[]map[string]string) {
	ctx.Logger().V(2).Info("starting scanning environments")

	// Filter Enviroments
	environments := filterItemsByUUID(w.Workspace.Environments, s.conn.ExcludeEnvironments, s.conn.IncludeEnvironments)

	// Scan Environments
	for _, env := range environments {
		envVars, err := s.client.GetEnvironment(env.UUID)
		if err != nil {
			s.log.Error(err, "could not get environment object", "environment_uuid", env.UUID)
		}
		// Will need to adjust FullID and Link for local JSON read in
		m := Metadata{
			WorkspaceUUID: w.Workspace.ID,
			WorkspaceName: w.Workspace.Name,
			CreatedBy:     w.Workspace.CreatedBy,
			Type:          ENVIRONMENT_TYPE,
			FullID:        env.UUID,
			Link:          LINK_BASE_URL + ENVIRONMENT_TYPE + "/" + env.UUID,
		}
		s.scanEnvironment(ctx, chunksChan, m, envVars.VariableData, extraKeywords, varSubMap)
	}
	ctx.Logger().V(2).Info("finished scanning environments")
}

func (s *Source) scanEnvironment(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, vars VariableData, extraKeywords []string, varSubMap *[]map[string]string) {
	ctx.Logger().V(2).Info("scanning environment vars", "environment_uuid", m.FullID)
	for _, word := range strings.Split(vars.Name, " ") {
		extraKeywords = append(extraKeywords, string(word))
	}
	s.scanVars(ctx, chunksChan, m, vars, extraKeywords, varSubMap)
	ctx.Logger().V(2).Info("finished scanning environment vars", "environment_uuid", m.FullID)
}

func (s *Source) scanVars(ctx context.Context, chunksChan chan *sources.Chunk, m Metadata, varData VariableData, extraKeywords []string, varSubMap *[]map[string]string) {
	if varData.KeyValues == nil {
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
	varSubstitutions := map[string]string{}

	allValuesMap := make(map[string]struct{})
	for _, v := range varData.KeyValues {
		key := v.Key
		value := fmt.Sprintf("%v", v.Value)
		extraKeywords = append(extraKeywords, key)
		extraKeywords = append(extraKeywords, value)
		allValuesMap[value] = struct{}{}
		varSubstitutions[key] = value
		if v.SessionValue != "" {
			sessionValue := fmt.Sprintf("%v", v.SessionValue)
			extraKeywords = append(extraKeywords, sessionValue)
			allValuesMap[sessionValue] = struct{}{}
			varSubstitutions[key] = sessionValue
		}
	}

	allValues := " "
	for value := range allValuesMap {
		allValues += (strings.Repeat(" ", KEYWORD_PADDING) + value)
	}

	// Filter out keywords that don't exist in pkg/detectors/*
	filteredKeywords := filterKeywords(extraKeywords, s.detectorKeywords)

	// Create slice of objects to scan (both context & data)
	pmObjToScan := []PMScanObject{}
	for _, v := range varData.KeyValues {
		data := fmt.Sprintf("%s:%s ", v.Key, fmt.Sprintf("%v", v.Value))
		for _, keyword := range filteredKeywords {
			if keyword == fmt.Sprintf("%v", v.Value) {
				continue
			}
			data += fmt.Sprintf("%s:%s ", keyword, fmt.Sprintf("%v", v.Value))
			data += strings.Repeat(" ", KEYWORD_PADDING)
		}
		data += allValues
		preScanObj := PMScanObject{
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
	if varSubMap == nil {
		varSubMap = &[]map[string]string{}
	}
	*varSubMap = append(*varSubMap, varSubstitutions)
	s.scanObjects(ctx, chunksChan, pmObjToScan)
}

func (s *Source) scanObjects(ctx context.Context, chunksChan chan *sources.Chunk, objects []PMScanObject) {
	//Remove duplicate objects to scan
	uniqueMap := make(map[PMScanObject]struct{})
	uniqueObjects := []PMScanObject{}

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
		go func(obj PMScanObject) {
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

func (s *Source) scanObject(ctx context.Context, chunksChan chan *sources.Chunk, o PMScanObject) {
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
