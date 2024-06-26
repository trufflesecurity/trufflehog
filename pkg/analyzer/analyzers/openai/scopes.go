package openai

import "github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"

type OpenAIScope struct {
	Name      string
	Tests     []analyzers.HttpStatusTest
	Endpoints []string
}

func (s *OpenAIScope) RunTests(key string) error {
	headers := map[string]string{
		"Authorization": "Bearer " + key,
		"Content-Type":  "application/json",
	}
	for i := range s.Tests {
		test := &s.Tests[i]
		if err := test.RunTest(headers); err != nil {
			return err
		}
	}
	return nil
}

var SCOPES = []OpenAIScope{
	{
		Name: "Models",
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/models", Method: "GET", Valid: []int{200}, Invalid: []int{403}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		Endpoints: []string{"/v1/models"},
	},
	{
		Name: "Model capabilities",
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/images/generations", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints: []string{"/v1/audio", "/v1/chat/completions", "/v1/embeddings", "/v1/images", "/v1/moderations"},
	},
	{
		Name: "Assistants",
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/assistants", Method: "GET", Valid: []int{400}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
			{URL: BASE_URL + "/v1/assistants", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints: []string{"/v1/assistants"},
	},
	{
		Name: "Threads",
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/threads/1", Method: "GET", Valid: []int{400}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
			{URL: BASE_URL + "/v1/threads", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints: []string{"/v1/threads"},
	},
	{
		Name: "Fine-tuning",
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/fine_tuning/jobs", Method: "GET", Valid: []int{200}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
			{URL: BASE_URL + "/v1/fine_tuning/jobs", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints: []string{"/v1/fine_tuning"},
	},
	{
		Name: "Files",
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/files", Method: "GET", Valid: []int{200}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
			{URL: BASE_URL + "/v1/files", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{415}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints: []string{"/v1/files"},
	},
}
