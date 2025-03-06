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

func TestSource_ScanEnumerateRateLimit(t *testing.T) {
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

	start := time.Now()
	_, err = s.client.EnumerateWorkspaces(ctx)
	if err != nil {
		t.Fatalf("enumeration error: %v", err)
	}
	elapsed := time.Since(start)
	// With <numWorkspaces> requests at 1 per second rate limit,
	// elapsed time should be at least <numWorkspaces - 1> seconds
	if elapsed < time.Duration(numWorkspaces-1)*time.Second {
		t.Errorf("Rate limiting not working as expected. Elapsed time: %v, expected at least %d seconds", elapsed, numWorkspaces-1)
	}
}
