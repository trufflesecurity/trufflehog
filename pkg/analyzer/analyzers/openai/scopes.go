package openai

import "github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"

type PermissionType int

const (
	ModelsPermission PermissionType = iota
	ModelCapabilitiesPermission
	AssistantsPermission
	ThreadsPermission
	FineTuningPermission
	FilesPermission
	FullAccess
)

func (p PermissionType) String() string {
	return [...]string{"Models", "Model capabilities", "Assistants", "Threads", "Fine-tuning", "Files", "Full Access"}[p]
}

func (p PermissionType) ID() int {
	return int(p)
}

type OpenAIScope struct {
	Permission  PermissionType
	Tests       []analyzers.HttpStatusTest
	Endpoints   []string
	AccessLevel analyzers.AccessLevel
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
		Permission: ModelsPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/models", Method: "GET", Valid: []int{200}, Invalid: []int{403}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/models"},
		AccessLevel: analyzers.READ,
	},
	{
		Permission: ModelCapabilitiesPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/images/generations", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/audio", "/v1/chat/completions", "/v1/embeddings", "/v1/images", "/v1/moderations"},
		AccessLevel: analyzers.WRITE,
	},
	{
		Permission: AssistantsPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/assistants", Method: "GET", Valid: []int{400}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/assistants"},
		AccessLevel: analyzers.READ,
	},
	{
		Permission: AssistantsPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/assistants", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/assistants"},
		AccessLevel: analyzers.WRITE,
	},
	{
		Permission: ThreadsPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/threads/1", Method: "GET", Valid: []int{400}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/threads"},
		AccessLevel: analyzers.READ,
	},
	{
		Permission: ThreadsPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/threads", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/threads"},
		AccessLevel: analyzers.WRITE,
	},
	{
		Permission: FineTuningPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/fine_tuning/jobs", Method: "GET", Valid: []int{200}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/fine_tuning"},
		AccessLevel: analyzers.READ,
	},
	{
		Permission: FineTuningPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/fine_tuning/jobs", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{400}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/fine_tuning"},
		AccessLevel: analyzers.WRITE,
	},
	{
		Permission: FilesPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/files", Method: "GET", Valid: []int{200}, Invalid: []int{401}, Type: analyzers.READ, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/files"},
		AccessLevel: analyzers.READ,
	},
	{
		Permission: FilesPermission,
		Tests: []analyzers.HttpStatusTest{
			{URL: BASE_URL + "/v1/files", Method: "POST", Payload: POST_PAYLOAD, Valid: []int{415}, Invalid: []int{401}, Type: analyzers.WRITE, Status: analyzers.PermissionStatus{}},
		},
		Endpoints:   []string{"/v1/files"},
		AccessLevel: analyzers.WRITE,
	},
}
