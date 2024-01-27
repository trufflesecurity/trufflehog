package postman

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
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
	GLOBAL_TYPE      = "global"
	ENVIRONMENT_TYPE = "environment"
	REQUEST_TYPE     = "request"
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

//ToDo: Update this to match the proto file

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

func verifyPostmanExportZip(filepath string) ArchiveJSON {
	var archiveData ArchiveJSON

	// Open the ZIP archive.
	r, err := zip.OpenReader(filepath)
	if err != nil {
		fmt.Println("Error opening ZIP file:", err)
		return archiveData
	}
	defer r.Close()

	// Iterate through the files in the ZIP archive.
	for _, file := range r.File {
		if strings.HasSuffix(file.Name, "archive.json") {
			// Open the file within the ZIP archive.
			rc, err := file.Open()
			if err != nil {
				fmt.Println("Error opening archive.json:", err)
				return archiveData
			}
			defer rc.Close()

			// Read the contents of archive.json.
			contents, err := io.ReadAll(rc)
			if err != nil {
				fmt.Println("Error reading archive.json:", err)
				return archiveData
			}

			// Unmarshal the JSON contents into the ArchiveJSON struct.
			if err := json.Unmarshal(contents, &archiveData); err != nil {
				fmt.Println("Error decoding JSON:", err)
				return archiveData
			}

			// Check if the structure matches your requirements.
			return archiveData
		}
	}
	return archiveData
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
	// Prep all of the objects to scan. Then scan them.
	if s.conn.Workspaces != nil {
		for _, workspace := range s.conn.Workspaces {
			s.scanWorkspace(ctx, chunksChan, workspace)
		}
	}
	return nil

	// if s.conn.Collection != "" {
	// 	//s.scanCollection(ctx, chunksChan)
	// 	// Filter out collections

	// }
	// if s.conn.Environment != "" {
	// 	//s.scanEnvironment(ctx, chunksChan)
	// 	// Filter out environments

	// }

}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk, wrkspc string) error {
	// var workspace WorkspaceObj
	var varSubMap []map[string]string
	extraKeywords := []map[string]interface{}{}

	logger := ctx.Logger().WithValues("workspace", wrkspc)

	// Used the IsValidUUID function below to check
	// if the user passed in a UUID (for interaction with API)
	// or a filepath (for interaction with local file)
	// if IsValidUUID(wrkspc) {

	w, err := s.client.GetWorkspace(wrkspc)
	if err != nil {
		s.log.Error(err, "could not get workspace object", "workspace_uuid", wrkspc)
	}
	logger.V(2).Info("scanning workspace")

	// Scan global vars
	ctx.Logger().V(2).Info("starting scanning global variables")
	extraKeywords = append(extraKeywords, map[string]interface{}{w.Workspace.Name: struct{}{}})
	globalVars, err := s.client.GetGlobals(wrkspc)
	if err != nil {
		s.log.Error(err, "could not get global variables object", "workspace_uuid", wrkspc)
	}
	s.scanVars(ctx, chunksChan, wrkspc, globalVars.VariableData, GLOBAL_TYPE, extraKeywords, &varSubMap)
	ctx.Logger().V(2).Info("finished scanning global variables")

	// Filter Enviroments
	environments := filterItemsByUUID(w.Workspace.Environments, s.conn.ExcludeEnvironments, s.conn.IncludeEnvironments)

	// Scan Environments
	for _, env := range environments {
		envVars, err := s.client.GetEnvironment(env.UUID)
		if err != nil {
			s.log.Error(err, "could not get environment object", "environment_uuid", env.UUID)
		}
		s.scanEnvironment(ctx, chunksChan, wrkspc, env.UUID, envVars, extraKeywords, &varSubMap)
	}

	// Filter Collections
	collections := filterItemsByUUID(w.Workspace.Collections, s.conn.ExcludeCollections, s.conn.IncludeCollections)
	fmt.Println(collections)

	// Else Clause to handle local files
	// } else {
	// 	// Check if user provided a valid Postman export zip file
	// 	archiveJSON := verifyPostmanExportZip(wrkspc)
	// 	if archiveJSON.Collection == nil && archiveJSON.Environment == nil {
	// 		logger.Error(errors.New("invalid workspace"), "invalid workspace", "workspace", wrkspc)
	// 		return errors.New("invalid workspace filepath")
	// 	}
	// 	// No Global Vars to scan when providing a local file
	// 	// Put ArchiveJSON into Workspace struct for consistency
	// 	workspace.Workspace.ID = wrkspc
	// 	for collection := range archiveJSON.Collection {
	// 		workspace.Workspace.Collections = append(workspace.Workspace.Collections, IDNameUUID{ID: collection})
	// 	}
	// 	for environment := range archiveJSON.Environment {
	// 		workspace.Workspace.Environments = append(workspace.Workspace.Environments, IDNameUUID{ID: environment})
	// 	}
	// }

	return nil
}

func (s *Source) scanEnvironment(ctx context.Context, chunksChan chan *sources.Chunk, workspaceUUID string, environmentUUID string, envVars Environment, extraKeywords []map[string]interface{}, varSubMap *[]map[string]string) {
	// Note: we won't have a envUUID, but we want to use the local path, so keep that in mind.
	logger := ctx.Logger().WithValues("workspace", workspaceUUID)
	logger.V(2).Info("scanning environment", "environment_uuid", environmentUUID)
	for _, word := range strings.Split(envVars.VariableData.Name, " ") {
		extraKeywords = append(extraKeywords, map[string]interface{}{string(word): struct{}{}})
	}
	s.scanVars(ctx, chunksChan, workspaceUUID, envVars.VariableData, ENVIRONMENT_TYPE, extraKeywords, nil)
	logger.V(2).Info("finished scanning environment", "environment_uuid", environmentUUID)
}

func (s *Source) scanVars(ctx context.Context, chunksChan chan *sources.Chunk, workspaceUUID string, variables VariableData, variable_type string, extraKeywords []map[string]interface{}, varSubMap *[]map[string]string) {
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
	localKeywords := make(map[string]struct{})
	for _, m := range extraKeywords {
		for k := range m {
			localKeywords[k] = struct{}{}
		}
	}

	allValuesMap := make(map[string]struct{})
	for _, globalVar := range variables.KeyValues {
		key := globalVar.Key
		value := fmt.Sprintf("%v", globalVar.Value)

		localKeywords[key] = struct{}{}
		localKeywords[value] = struct{}{}
		allValuesMap[value] = struct{}{}
		varSubstitutions[key] = value

		if globalVar.SessionValue != "" {
			sessionValue := fmt.Sprintf("%v", globalVar.SessionValue)
			localKeywords[sessionValue] = struct{}{}
			allValuesMap[sessionValue] = struct{}{}
			varSubstitutions[key] = sessionValue
		}
	}

	allValues := " "
	for value := range allValuesMap {
		allValues += (strings.Repeat(" ", KEYWORD_PADDING) + value)
	}

	// Filter out keywords that don't exist in pkg/detectors/*
	localKeywords = filterKeywords(localKeywords, s.detectorKeywords)

	// Create slice of objects to scan (both context & data)
	pmObjToScan := []PMScanObject{}
	for _, v := range variables.KeyValues {
		var data string
		for keyword := range localKeywords {
			if keyword == fmt.Sprintf("%v", v.Value) {
				continue
			}
			data += fmt.Sprintf("%s:%s ", keyword, fmt.Sprintf("%v", v.Value))
			data += strings.Repeat(" ", KEYWORD_PADDING)
		}
		data += allValues
		preScanObj := PMScanObject{
			Link:          LINK_BASE_URL + variable_type + "s/" + variables.ID,
			WorkspaceUUID: workspaceUUID,
			GlobalID:      variables.ID,
			FieldType:     variable_type + " variable",
			FieldName:     v.Key,
			VarType:       v.Type,
			Data:          data,
		}
		pmObjToScan = append(pmObjToScan, preScanObj)
		// This is a legacy field from Postman. But they can still exist (although invisible in UI).
		if v.SessionValue != "" {
			var data string
			for keyword := range localKeywords {
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
					FieldType:       o.FieldType,
					FieldName:       o.FieldName,
					VariableType:    o.VarType,
				},
			},
		},
		Verify: s.verify,
	}
}

// func (s *Source) scanCollection(ctx context.Context, chunksChan chan *sources.Chunk) {
// 	// Filter out collcetions
// }

// func (s *Source) scanEnvironment(ctx context.Context, chunksChan chan *sources.Chunk) {
// 	// Filter out environments
// }

// func (s *Source) collectionChunker(ctx context.Context, chunksChan chan *sources.Chunk, collections []string, errorCount *sync.Map, objectCount *uint64) {
// 	for _, collection := range collections {

// 		if common.IsDone(ctx) {
// 			return
// 		}

// 		if collection == nil {
// 			continue
// 		}

// 		s.jobPool.Go(func() error {
// 			defer common.RecoverWithExit(ctx)

// 			if strings.HasSuffix(*obj.Key, "/") {
// 				s.log.V(5).Info("Skipping directory", "object", *obj.Key)
// 				return nil
// 			}

// 			path := strings.Split(*obj.Key, "/")
// 			prefix := strings.Join(path[:len(path)-1], "/")

// 			nErr, ok := errorCount.Load(prefix)
// 			if !ok {
// 				nErr = 0
// 			}
// 			if nErr.(int) > 3 {
// 				s.log.V(2).Info("Skipped due to excessive errors", "object", *obj.Key)
// 				return nil
// 			}

// 			// files break with spaces, must replace with +
// 			// objKey := strings.ReplaceAll(*obj.Key, " ", "+")
// 			ctx, cancel := context.WithTimeout(ctx, time.Second*5)
// 			defer cancel()
// 			res, err := client.GetObjectWithContext(ctx, &s3.GetObjectInput{
// 				Bucket: &bucket,
// 				Key:    obj.Key,
// 			})
// 			if err != nil {
// 				if !strings.Contains(err.Error(), "AccessDenied") {
// 					s.log.Error(err, "could not get S3 object", "object", *obj.Key)
// 				}

// 				nErr, ok := errorCount.Load(prefix)
// 				if !ok {
// 					nErr = 0
// 				}
// 				if nErr.(int) > 3 {
// 					s.log.V(3).Info("Skipped due to excessive errors", "object", *obj.Key)
// 					return nil
// 				}
// 				nErr = nErr.(int) + 1
// 				errorCount.Store(prefix, nErr)
// 				// too many consective errors on this page
// 				if nErr.(int) > 3 {
// 					s.log.V(2).Info("Too many consecutive errors, excluding prefix", "prefix", prefix)
// 				}
// 				return nil
// 			}

// 			bufferName := cleantemp.MkFilename()

// 			defer res.Body.Close()
// 			reader, err := diskbufferreader.New(res.Body, diskbufferreader.WithBufferName(bufferName))
// 			if err != nil {
// 				s.log.Error(err, "Could not create reader.")
// 				return nil
// 			}
// 			defer reader.Close()

// 			email := "Unknown"
// 			if obj.Owner != nil {
// 				email = *obj.Owner.DisplayName
// 			}
// 			modified := obj.LastModified.String()
// 			chunkSkel := &sources.Chunk{
// 				SourceType: s.Type(),
// 				SourceName: s.name,
// 				SourceID:   s.SourceID(),
// 				JobID:      s.JobID(),
// 				SourceMetadata: &source_metadatapb.MetaData{
// 					Data: &source_metadatapb.MetaData_S3{
// 						S3: &source_metadatapb.S3{
// 							Bucket:    bucket,
// 							File:      sanitizer.UTF8(*obj.Key),
// 							Link:      sanitizer.UTF8(makeS3Link(bucket, *client.Config.Region, *obj.Key)),
// 							Email:     sanitizer.UTF8(email),
// 							Timestamp: sanitizer.UTF8(modified),
// 						},
// 					},
// 				},
// 				Verify: s.verify,
// 			}
// 			if handlers.HandleFile(ctx, reader, chunkSkel, sources.ChanReporter{Ch: chunksChan}) {
// 				atomic.AddUint64(objectCount, 1)
// 				s.log.V(5).Info("S3 object scanned.", "object_count", objectCount, "page_number", pageNumber)
// 				return nil
// 			}

// 			if err := reader.Reset(); err != nil {
// 				s.log.Error(err, "Error resetting reader to start.")
// 			}
// 			reader.Stop()

// 			chunkReader := sources.NewChunkReader()
// 			chunkResChan := chunkReader(ctx, reader)
// 			for data := range chunkResChan {
// 				if err := data.Error(); err != nil {
// 					s.log.Error(err, "error reading chunk.")
// 					continue
// 				}
// 				chunk := *chunkSkel
// 				chunk.Data = data.Bytes()
// 				if err := common.CancellableWrite(ctx, chunksChan, &chunk); err != nil {
// 					return err
// 				}
// 			}

// 			atomic.AddUint64(objectCount, 1)
// 			s.log.V(5).Info("S3 object scanned.", "object_count", objectCount, "page_number", pageNumber)
// 			nErr, ok = errorCount.Load(prefix)
// 			if !ok {
// 				nErr = 0
// 			}
// 			if nErr.(int) > 0 {
// 				errorCount.Store(prefix, 0)
// 			}

// 			return nil
// 		})
// 	}

// 	_ = s.jobPool.Wait()
// }

// // postmanChunker()

// //maybe a process object function that takes a chunk and processes it?

// // Need a function to get globals and process them, and then teh same for the rest

func filterKeywords(keys map[string]struct{}, detectorKeywords map[string]struct{}) map[string]struct{} {
	// Filter out keywords that don't exist in pkg/detectors/*
	filteredKeywords := make(map[string]struct{})

	// Iterate through the input keys
	for key := range keys {
		// Check if the key contains any detectorKeyword
		containsDetector := false
		for detectorKey := range detectorKeywords {
			if strings.Contains(key, detectorKey) {
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
	uniqueKeywords := make(map[string]struct{})

	// Iterate through the filtered keywords
	for name := range filteredKeywords {
		foundSimilar := false

		// Check if the name is similar to any of the unique canonical names
		for key := range uniqueKeywords {
			if strings.Contains(key, name) || strings.Contains(name, key) {
				// A similar name is found, skip adding it to the map
				foundSimilar = true
				break
			}
		}

		if !foundSimilar {
			// No similar name found, add it to the map
			uniqueKeywords[name] = struct{}{}
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
