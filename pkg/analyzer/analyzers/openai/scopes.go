package openai

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
)

type OpenAIScope struct {
	ReadTests       []analyzers.HttpStatusTest
	WriteTests      []analyzers.HttpStatusTest
	Endpoints       []string
	ReadPermission  Permission
	WritePermission Permission
}

func (s *OpenAIScope) RunTests(key string) error {
	headers := map[string]string{
		"Authorization": "Bearer " + key,
		"Content-Type":  "application/json",
	}
	for i := range s.ReadTests {
		test := &s.ReadTests[i]
		if err := test.RunTest(headers); err != nil {
			return err
		}
	}
	for i := range s.WriteTests {
		test := &s.WriteTests[i]
		if err := test.RunTest(headers); err != nil {
			return err
		}
	}
	return nil
}

var SCOPES = []OpenAIScope{
	{
		ReadTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/models", Method: "GET", Valid: []int{200}, Invalid: []int{403}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:      []string{"/v1/models"},
		ReadPermission: ModelsRead,
	},
	{
		WriteTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/images/generations", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:       []string{"/v1/audio", "/v1/chat/completions", "/v1/embeddings", "/v1/images", "/v1/moderations"},
		WritePermission: ModelCapabilitiesWrite,
	},
	{
		ReadTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/assistants", Method: "GET", Valid: []int{400}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		WriteTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/assistants", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:       []string{"/v1/assistants"},
		ReadPermission:  AssistantsRead,
		WritePermission: AssistantsWrite,
	},
	{
		ReadTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/threads/1", Method: "GET", Valid: []int{400}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		WriteTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/threads", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:       []string{"/v1/threads"},
		ReadPermission:  ThreadsRead,
		WritePermission: ThreadsWrite,
	},
	{
		ReadTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/fine_tuning/jobs", Method: "GET", Valid: []int{200}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		WriteTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/fine_tuning/jobs", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:       []string{"/v1/fine_tuning"},
		ReadPermission:  FineTuningRead,
		WritePermission: FineTuningWrite,
	},
	{
		ReadTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/files", Method: "GET", Valid: []int{200}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		WriteTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/files", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{415}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:       []string{"/v1/files"},
		ReadPermission:  FilesRead,
		WritePermission: FilesWrite,
	},
	{
		ReadTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/evals", Method: "GET", Valid: []int{200}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		WriteTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/evals", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:       []string{"/v1/evals"},
		ReadPermission:  EvalsRead,
		WritePermission: EvalsWrite,
	},
	{
		ReadTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/responses/1", Method: "GET", Valid: []int{400}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		WriteTests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/responses", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:       []string{"/v1/responses"},
		ReadPermission:  ResponsesRead,
		WritePermission: ResponsesWrite,
	},
}
