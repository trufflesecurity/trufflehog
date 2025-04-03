package postman

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"google.golang.org/protobuf/types/known/anypb"
)

func createTestSource(src *sourcespb.Postman) (*Source, *anypb.Any) {
	s := &Source{}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}
	return s, conn
}

func TestSource_Init(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Postman{
		Credential: &sourcespb.Postman_Token{
			Token: "super secret token",
		},
	})
	s.DetectorKeywords = map[string]struct{}{
		"keyword1": {},
		"keyword2": {},
	}

	err := s.Init(context.Background(), "test - postman", 0, 1, false, conn, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedKeywords := map[string]struct{}{
		"keyword1": {},
		"keyword2": {},
	}
	if !reflect.DeepEqual(s.DetectorKeywords, expectedKeywords) {
		t.Errorf("expected detector keywords: %v, got: %v", expectedKeywords, s.DetectorKeywords)
	}
}

func TestSource_ScanCollection(t *testing.T) {
	ctx := context.Background()
	s := &Source{
		DetectorKeywords: map[string]struct{}{
			"keyword1": {},
		},
		keywords: map[string]struct{}{
			"keyword1": {},
		},
	}

	testCases := []struct {
		name           string
		collection     Collection
		expectedChunks []string
	}{
		{
			name: "GET request with URL",
			collection: Collection{
				Info: Info{
					PostmanID: "col1",
					Name:      "Test Collection",
				},
				Items: []Item{
					{
						Name: "Request 1",
						Request: Request{
							URL: URL{
								Protocol: "https",
								Host:     []string{"example.com"},
								Path:     []string{"api", "endpoint"},
								Raw:      "https://example.com/api/endpoint",
							},
							Method: "GET",
						},
					},
				},
			},
			expectedChunks: []string{
				"keyword1:https://example.com/api/endpoint\n",
			},
		},
		{
			name: "POST request with URL and auth",
			collection: Collection{
				Info: Info{
					PostmanID: "col2",
					Name:      "Test Collection",
				},
				Items: []Item{
					{
						Name: "Request 2",
						Request: Request{
							URL: URL{
								Protocol: "https",
								Host:     []string{"example.com"},
								Path:     []string{"api", "endpoint"},
								Raw:      "https://example.com/api/endpoint",
							},
							Method: "POST",
							Auth: Auth{
								Type: "bearer",
								Bearer: []KeyValue{
									{
										Key:   "token",
										Value: "abcdef123456",
									},
								},
							},
						},
					},
				},
			},
			expectedChunks: []string{
				"keyword1:https://example.com/api/endpoint\n",
				"keyword1:token:abcdef123456 \n",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunksChan := make(chan *sources.Chunk, len(tc.expectedChunks))
			metadata := Metadata{
				CollectionInfo: tc.collection.Info,
			}

			go s.scanCollection(ctx, chunksChan, metadata, tc.collection)

			for _, expectedData := range tc.expectedChunks {
				chunk := <-chunksChan

				// can't guarantee order of keywords in chunk data
				// so we need to compare the data after sorting
				got := strings.Split(strings.TrimSpace(string(chunk.Data)), "\n")
				expected := strings.Split(strings.TrimSpace(expectedData), "\n")
				sort.Strings(got)
				sort.Strings(expected)

				if !reflect.DeepEqual(got, expected) {
					t.Errorf("expected chunk data from collection: \n%sgot: \n%s", expectedData, chunk.Data)
				}
			}
		})
	}
}

func TestSource_ScanVariableData(t *testing.T) {
	ctx := context.Background()
	s := &Source{
		DetectorKeywords: map[string]struct{}{
			"keyword1": {},
		},
		keywords: map[string]struct{}{
			"keyword1": {},
		},
		sub: NewSubstitution(),
	}

	testCases := []struct {
		name           string
		metadata       Metadata
		variableData   VariableData
		expectedChunks []string
	}{
		{
			name: "Single variable",
			metadata: Metadata{
				CollectionInfo: Info{
					PostmanID: "col1",
					Name:      "Test Collection",
				},
			},
			variableData: VariableData{
				KeyValues: []KeyValue{
					{
						Key:   "var1",
						Value: "value1",
					},
				},
			},
			expectedChunks: []string{
				"keyword1:value1\n",
			},
		},
		{
			name: "Multiple variables",
			metadata: Metadata{
				CollectionInfo: Info{
					PostmanID: "col2",
					Name:      "Test Collection",
				},
			},
			variableData: VariableData{
				KeyValues: []KeyValue{
					{
						Key:   "var1",
						Value: "value1",
					},
					{
						Key:   "var2",
						Value: "value2",
					},
				},
			},
			expectedChunks: []string{
				"keyword1:value1\nkeyword1:value2\n",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunksChan := make(chan *sources.Chunk, len(tc.expectedChunks))

			s.scanVariableData(ctx, chunksChan, tc.metadata, tc.variableData)

			for _, expectedData := range tc.expectedChunks {
				chunk := <-chunksChan
				got := strings.Split(strings.TrimSpace(string(chunk.Data)), "\n")
				expected := strings.Split(strings.TrimSpace(expectedData), "\n")
				sort.Strings(got)
				sort.Strings(expected)

				if !reflect.DeepEqual(got, expected) {
					t.Errorf("expected chunk data from collection: \n%sgot: \n%s", expectedData, chunk.Data)
				}
			}
		})
	}
}

func TestSource_ScanEnumerateWorkspaceRateLimit(t *testing.T) {
	defer gock.Off()
	// Mock the API response for workspaces
	numWorkspaces := 3
	workspaceBodyString := `{"workspaces":[`
	for i := 0; i < numWorkspaces; i++ {
		workspaceBodyString += fmt.Sprintf(`{"id": "%d", "name": "workspace-%d", "type": "personal", "visibility": "personal", "createdBy": "1234"}`, i, i)
		if i == numWorkspaces-1 {
			workspaceBodyString += `]}`
		} else {
			workspaceBodyString += `,`
		}
	}
	gock.New("https://api.getpostman.com").
		Get("/workspaces").
		Reply(200).
		BodyString(workspaceBodyString)
	// Mock the API response for each individual workspace
	for i := 0; i < numWorkspaces; i++ {
		gock.New("https://api.getpostman.com").
			Get(fmt.Sprintf("/workspaces/%d", i)).
			Reply(200).
			BodyString(fmt.Sprintf(`{"workspace":{"id":"%d","name":"workspace-%d","type":"personal","description":"Test workspace number %d",
			"visibility":"personal","createdBy":"1234","updatedBy":"1234","createdAt":"2024-12-12T23:32:27.000Z","updatedAt":"2024-12-12T23:33:01.000Z",
			"collections":[{"id":"abc%d","name":"test-collection-1","uid":"1234-abc%d"},{"id":"def%d","name":"test-collection-2","uid":"1234-def%d"}],
			"environments":[{"id":"ghi%d","name":"test-environment-1","uid":"1234-ghi%d"},{"id":"jkl%d","name":"test-environment-2","uid":"1234-jkl%d"}]}}`, i, i, i, i, i, i, i, i, i, i, i))
	}

	ctx := context.Background()
	s, conn := createTestSource(&sourcespb.Postman{
		Credential: &sourcespb.Postman_Token{
			Token: "super-secret-token",
		},
	})
	err := s.Init(ctx, "test - postman", 0, 1, false, conn, 1)
	if err != nil {
		t.Fatalf("init error: %v", err)
	}
	gock.InterceptClient(s.client.HTTPClient)
	defer gock.RestoreClient(s.client.HTTPClient)

	start := time.Now()
	_, err = s.client.EnumerateWorkspaces(ctx)
	if err != nil {
		t.Fatalf("enumeration error: %v", err)
	}
	elapsed := time.Since(start)
	// With <numWorkspaces> requests at 1 per second rate limit,
	// elapsed time should be at least <numWorkspaces - 1> seconds
	if elapsed < time.Duration(numWorkspaces-1)*time.Second {
		t.Errorf("Rate limiting not working as expected. Elapsed time: %v seconds, expected at least %d seconds", elapsed.Seconds(), numWorkspaces-1)
	}
}

func TestSource_ScanGeneralRateLimit(t *testing.T) {
	defer gock.Off()
	// Mock the API response for a specific environment id
	gock.New("https://api.getpostman.com").
		Get("environments/abc").
		Persist().
		Reply(200).
		BodyString(`{"environment":{"uid":"1234-abc","id":"abc","name":"test-environment","owner":"1234","createdAt":"2025-02-13T23:17:36.000Z",
		"updatedAt":"2025-02-13T23:18:14.000Z","values":[{"key":"test-key","value":"a-secret-value","enabled":true,"type":"default"}],"isPublic":false}}`)
	ctx := context.Background()
	s, conn := createTestSource(&sourcespb.Postman{
		Credential: &sourcespb.Postman_Token{
			Token: "super-secret-token",
		},
	})
	err := s.Init(ctx, "test - postman", 0, 1, false, conn, 1)
	if err != nil {
		t.Fatalf("init error: %v", err)
	}
	gock.InterceptClient(s.client.HTTPClient)
	defer gock.RestoreClient(s.client.HTTPClient)

	numRequests := 3
	start := time.Now()
	for i := 0; i < numRequests; i++ {
		_, err = s.client.GetEnvironmentVariables(ctx, "abc")
		if err != nil {
			t.Fatalf("get environment variables error: %v", err)
		}
	}
	elapsed := time.Since(start)
	// With number of requests at 5 per second rate limit,
	// elapsed time should be at least <(numRequests - 1)/5> seconds
	if elapsed < time.Duration((numRequests-1)/5)*time.Second {
		t.Errorf("Rate limiting not working as expected. Elapsed time: %v seconds, expected at least %v seconds", elapsed.Seconds(), (float64(numRequests)-1)/5)
	}
}

func TestSource_UnmarshalMultipleHeaderTypes(t *testing.T) {
	defer gock.Off()
	// Mock a collection with request and response headers of KeyValue type
	gock.New("https://api.getpostman.com").
		Get("/collections/1234-abc1").
		Reply(200).
		BodyString(`{"collection":{"info":{"_postman_id":"abc1","name":"test-collection-1","schema":"https://schema.postman.com/json/collection/v2.1.0/collection.json",
	 	"updatedAt":"2025-03-21T17:39:25.000Z","createdAt":"2025-03-21T17:37:13.000Z","lastUpdatedBy":"1234","uid":"1234-abc1"},
	 	"item":[{"name":"echo","id":"req-ues-t1","protocolProfileBehavior":{"disableBodyPruning":true},"request":{"method":"GET","header":[{"key":"Date","value":"Fri, 21 Mar 2025 17:38:58 GMT"}]},
	 	"response":[{"id":"res-pon-se1","name":"echo-response","originalRequest":{"method":"GET","header":[{"key":"Date","value":"Fri, 21 Mar 2025 17:38:58 GMT"}],
	 	"url":{"raw":"postman-echo.com/get","host":["postman-echo","com"],"path":["get"]}},"status":"OK","code":200,"_postman_previewlanguage":"json",
	 	"header":[{"key":"Date","value":"Fri, 21 Mar 2025 17:38:58 GMT"},{"key":"Content-Type","value":"application/json; charset=utf-8"},{"key":"Content-Length","value":"508"},
	 	{"key":"Connection","value":"keep-alive"},{"key":"Server","value":"nginx"},{"key":"ETag","value":"random-string"},
		{"key":"set-cookie","value":"sails.sid=long-string; Path=/; HttpOnly"}],"cookie":[], "responseTime":null,"body":"{response-body}","uid":"1234-res-pon-se1"}],"uid":"1234-req-ues-t1"}]}}`)
	// Mock a collection with request and response headers of string type
	gock.New("https://api.getpostman.com").
		Get("/collections/1234-def1").
		Reply(200).
		BodyString(`{"collection":{"info":{"_postman_id":"abc1","name":"test-collection-1","schema":"https://schema.postman.com/json/collection/v2.1.0/collection.json",
	 	"updatedAt":"2025-03-21T17:39:25.000Z","createdAt":"2025-03-21T17:37:13.000Z","lastUpdatedBy":"1234","uid":"1234-def1"},
	 	"item":[{"name":"echo","id":"req-ues-t1","protocolProfileBehavior":{"disableBodyPruning":true},"request":{"method":"GET","header":["request-header-string"]},
	 	"response":[{"id":"res-pon-se1","name":"echo-response","originalRequest":{"method":"GET","header":["request-header-string"],
	 	"url":{"raw":"postman-echo.com/get","host":["postman-echo","com"],"path":["get"]}},"status":"OK","code":200,"_postman_previewlanguage":"json",
	 	"header":["response-header-string"],"cookie":[], "responseTime":null,"body":"{response-body}","uid":"1234-res-pon-se1"}],"uid":"1234-req-ues-t1"}]}}`)

	ctx := context.Background()
	s, conn := createTestSource(&sourcespb.Postman{
		Credential: &sourcespb.Postman_Token{
			Token: "super-secret-token",
		},
	})
	err := s.Init(ctx, "test - postman", 0, 1, false, conn, 1)
	if err != nil {
		t.Fatalf("init error: %v", err)
	}
	gock.InterceptClient(s.client.HTTPClient)
	defer gock.RestoreClient(s.client.HTTPClient)

	collectionIds := []string{"1234-abc1", "1234-def1"}
	for _, collectionId := range collectionIds {
		_, err := s.client.GetCollection(ctx, collectionId)
		if err != nil {
			t.Fatalf("failed to get collection: %v", err)
		}
	}
}

// The purpose of the TestSource_HeadersScanning test is to check that at least one of the fields HeaderKeyValue or HeaderString are non-null after unmarshalling and that chunks can
// be generated from them.
func TestSource_HeadersScanning(t *testing.T) {
	defer gock.Off()
	// Mock a collection with request and response headers of KeyValue type
	gock.New("https://api.getpostman.com").
		Get("/collections/1234-abc1").
		Reply(200).
		BodyString(`{"collection":{"info":{"_postman_id":"abc1","name":"test-collection-1","schema":"https://schema.postman.com/json/collection/v2.1.0/collection.json",
        "updatedAt":"2025-03-21T17:39:25.000Z","createdAt":"2025-03-21T17:37:13.000Z","lastUpdatedBy":"1234","uid":"1234-abc1"},
        "item":[{"name":"echo","id":"req-ues-t1", "request":{"method":"GET","header":[{"key":"token","value":"keyword1"}]},
        "response":[{"id":"res-pon-se1","name":"echo-response","originalRequest":{"method":"GET","header":[{"key":"token","value":"keyword1"}]},
        "header":[{"key":"token","value":"keyword1"}]}],"uid":"1234-req-ues-t1"}]}}`)
	// Mock a collection with request and response headers of string type
	gock.New("https://api.getpostman.com").
		Get("/collections/1234-def1").
		Reply(200).
		BodyString(`{"collection":{"info":{"_postman_id":"abc1","name":"test-collection-1","schema":"https://schema.postman.com/json/collection/v2.1.0/collection.json",
        "updatedAt":"2025-03-21T17:39:25.000Z","createdAt":"2025-03-21T17:37:13.000Z","lastUpdatedBy":"1234","uid":"1234-def1"},
        "item":[{"name":"echo","id":"req-ues-t1","protocolProfileBehavior":{"disableBodyPruning":true},"request":{"method":"GET","header":["keyword1-request-header-string"]},
        "response":[{"id":"res-pon-se1","name":"echo-response","originalRequest":{"method":"GET","header":["keyword1-request-header-string"]},
        "header":["keyword1-response-header-string"]}],"uid":"1234-req-ues-t1"}]}}`)

	ctx := context.Background()
	s, conn := createTestSource(&sourcespb.Postman{
		Credential: &sourcespb.Postman_Token{
			Token: "super-secret-token",
		},
	})

	// Add detector keywords to trigger chunk generation
	s.DetectorKeywords = map[string]struct{}{
		"keyword1": {},
	}
	s.keywords = map[string]struct{}{
		"keyword1": {},
	}

	err := s.Init(ctx, "test - postman", 0, 1, false, conn, 1)
	if err != nil {
		t.Fatalf("init error: %v", err)
	}
	gock.InterceptClient(s.client.HTTPClient)
	defer gock.RestoreClient(s.client.HTTPClient)

	chunksChan := make(chan *sources.Chunk, 10)
	collectionIds := []string{"1234-abc1", "1234-def1"}

	for _, collectionId := range collectionIds {
		collection, err := s.client.GetCollection(ctx, collectionId)
		if err != nil {
			t.Fatalf("failed to get collection: %v", err)
		}
		s.scanCollection(ctx, chunksChan, Metadata{CollectionInfo: collection.Info}, collection)
	}

	close(chunksChan)
	chunksReceived := len(chunksChan)

	if chunksReceived == 0 {
		t.Errorf("No chunks were generated from the mock data")
	} else {
		t.Logf("Generated %d chunks from the mock data", chunksReceived)
	}
}
