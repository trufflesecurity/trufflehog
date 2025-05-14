package postman

import (
	"encoding/json"
	"github.com/repeale/fp-go"
	"github.com/volatiletech/null/v8"
)

type PostmanWorkspaceJson struct {
	Workspace struct {
		Id          string `json:"id"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Visibility  string `json:"visibility"`
		CreatedBy   string `json:"createdBy"`
		UpdatedBy   string `json:"updatedBy"`
		CreatedAt   string `json:"createdAt"`
		UpdatedAt   string `json:"updatedAt"`
		Collections []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
			Uid  string `json:"uid"`
		} `json:"collections"`
		Environments []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
			Uid  string `json:"uid"`
		} `json:"environments"`
		Mocks []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			Uid         string `json:"uid"`
			Deactivated bool   `json:"deactivated"`
		} `json:"mocks"`
		Monitors []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			Uid         string `json:"uid"`
			Deactivated bool   `json:"deactivated"`
		} `json:"monitors"`
		Apis []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
			Uid  string `json:"uid"`
		} `json:"apis"`
		Scim struct {
			CreatedBy string `json:"createdBy"`
			UpdatedBy string `json:"updatedBy"`
		} `json:"scim"`
	} `json:"workspace"`
}

type PostmanCollectionJson struct {
	Collection struct {
		Info struct {
			PostmanId     string `json:"_postman_id"`
			Name          string `json:"name"`
			Description   string `json:"description"`
			Schema        string `json:"schema"`
			UpdatedAt     string `json:"updatedAt"`
			CreatedAt     string `json:"createdAt"`
			LastUpdatedBy string `json:"lastUpdatedBy"`
			Uid           string `json:"uid"`
		} `json:"collection"`
		Auth     PostmanCollectionAuthJson    `json:"auth"`
		Item     []PostmanCollectionItemJson  `json:"item"`
		Event    []PostmanCollectionEventJson `json:"event"`
		Variable []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"variable"`
	} `json:"collection"`
}
type PostmanGetCollectionItemRequest struct {
	Auth   PostmanCollectionAuthJson `json:"auth"`
	Method string                    `json:"method"`
	Body   struct {
		Mode    string `json:"mode"`
		Raw     string `json:"raw"`
		Options struct {
			Raw struct {
				Language string `json:"language"`
			} `json:"raw"`
		} `json:"options"`
	} `json:"body"`
	Url struct {
		Raw      string   `json:"raw"`
		Protocol string   `json:"protocol"`
		Host     []string `json:"host"`
		Path     []string `json:"path"`
		Query    []struct {
			Key         string `json:"key"`
			Value       string `json:"value"`
			Description string `json:"description"`
		} `json:"query"`
	} `json:"url"`

	// We have to handle headers in post-processing, because sometimes they come in different shapes
	// TODO - Actually do this
	HeaderRaw string `json:"header"`
	Header    []PostmanGetCollectionHeader
}
type PostmanCollectionEventJson struct {
	Listen string `json:"listen"`
	Script struct {
		Type string   `json:"type"`
		Exec []string `json:"exec"`
	} `json:"script"`
}
type PostmanCollectionItemJson struct {
	Name                    string                    `json:"name"`
	Id                      string                    `json:"id"`
	Uid                     string                    `json:"uid"`
	Description             string                    `json:"description"`
	Auth                    PostmanCollectionAuthJson `json:"auth"`
	ProtocolProfileBehavior struct {
		DisableBodyPruning bool `json:"disableBodyPruning"`
	} `json:"protocolProfileBehavior"`
	Request  PostmanGetCollectionItemRequest `json:"request"`
	Response []struct {
		Id                     string                          `json:"id"`
		Uid                    string                          `json:"uid"`
		Name                   string                          `json:"name"`
		OriginalRequest        PostmanGetCollectionItemRequest `json:"originalRequest"`
		Status                 string                          `json:"status"`
		Code                   int8                            `json:"code"`
		PostmanPreviewLanguage string                          `json:"_postman_previewlanguage"`
		Cookie                 []struct{}                      `json:"cookie"`
		ResponseTime           null.String                     `json:"responseTime"`
		Body                   string                          `json:"body"`

		// We have to handle headers in post-processing, because sometimes they come in different shapes
		// TODO - Actually do this
		HeaderRaw string `json:"header"`
		Header    []PostmanGetCollectionHeader
	} `json:"response"`
	Item  []PostmanCollectionItemJson  `json:"item"`
	Event []PostmanCollectionEventJson `json:"event"`
}

type CredentialJson struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type PostmanCollectionAuthJson struct {
	Type   string           `json:"type"`
	ApiKey []CredentialJson `json:"apikey"`
	Bearer []CredentialJson `json:"bearer"`
	AwsV4  []CredentialJson `json:"awsv4"`
	Basic  []CredentialJson `json:"basic"`
	OAuth2 []CredentialJson `json:"oauth2"`
}
type PostmanGetCollectionHeader struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type PostmanEnvironmentJson struct {
	Environment struct {
		Id        string `json:"id"`
		Name      string `json:"name"`
		Owner     string `json:"owner"`
		CreatedAt string `json:"createdAt"`
		UpdatedAt string `json:"updatedAt"`
		Values    []struct {
			Key          string `json:"key"`
			Value        string `json:"value"`
			Enabled      bool   `json:"enabled"`
			Type         string `json:"type"`
			SessionValue string `json:"sessionValue"`
		} `json:"values"`
	} `json:"environment"`
}

func GetCollectionFromJsonBytes(bytes []byte) (PostmanCollection, error) {

	var parsedJson PostmanCollectionJson
	if err := json.Unmarshal(bytes, &parsedJson); err != nil {
		return PostmanCollection{}, err
	}

	return PostmanCollection{
		Uid:  parsedJson.Collection.Info.Uid,
		Name: parsedJson.Collection.Info.Name,

		Auth:      getCollectionAuthFromParsedJson(parsedJson.Collection.Auth),
		Variables: getCollectionVariablesFromParsedJson(parsedJson),
		Events:    getCollectionEventsFromParsedJson(parsedJson),

		Items: fp.Map(getCollectionItemFromParsedJson)(parsedJson.Collection.Item),
	}, nil
}

func getCollectionItemFromParsedJson(parsedItemJson PostmanCollectionItemJson) PostmanCollectionItem {
	return PostmanCollectionItem{
		Name: parsedItemJson.Name,
		Id:   parsedItemJson.Id,
		Uid:  parsedItemJson.Uid,

		Items: fp.Map(getCollectionItemFromParsedJson)(parsedItemJson.Item),

		Request: PostmanCollectionRequest{
			Method: parsedItemJson.Request.Method,
			Url: PostmanCollectionUrl{
				Protocol: parsedItemJson.Request.Url.Protocol,
				Host:     parsedItemJson.Request.Url.Host,
				Path:     parsedItemJson.Request.Url.Path,
				Raw:      parsedItemJson.Request.Url.Raw,
				Query: fp.Map(func(q struct{ Key, Value, Description string }) struct{ Key, Value string } {

				})(parsedItemJson.Request.Url.Query),
			},
			Auth:    getCollectionAuthFromParsedJson(parsedItemJson.Request.Auth),
			Body:    PostmanRequestBody{},
			Headers: nil,
		},
	}
}

func getCollectionEventsFromParsedJson(parsedJson PostmanCollectionJson) []PostmanCollectionEvent {
	return fp.Map(func(e PostmanCollectionEventJson) PostmanCollectionEvent {
		return PostmanCollectionEvent{
			Listen: e.Listen,
			Script: struct{ Exec []string }{Exec: e.Script.Exec},
		}
	})(parsedJson.Collection.Event)
}

func getCollectionVariablesFromParsedJson(parsedJson PostmanCollectionJson) []struct{ Key, Value string } {
	return fp.Map(func(v struct{ Key, Value, Type string }) struct{ Key, Value string } {
		return struct{ Key, Value string }{v.Key, v.Value}
	})([]struct{ Key, Value, Type string }(parsedJson.Collection.Variable))
}

func getCollectionAuthFromParsedJson(parsedAuthJson PostmanCollectionAuthJson) PostmanCollectionAuth {
	return PostmanCollectionAuth{
		Type: parsedAuthJson.Type,
		ApiKey: fp.Map(func(c CredentialJson) struct{ Key, Value string } {
			return struct{ Key, Value string }{c.Key, c.Value}
		})(parsedAuthJson.ApiKey),
		AwsV4: fp.Map(func(c CredentialJson) struct{ Key, Value string } {
			return struct{ Key, Value string }{c.Key, c.Value}
		})(parsedAuthJson.AwsV4),
		Bearer: fp.Map(func(c CredentialJson) struct{ Key, Value string } {
			return struct{ Key, Value string }{c.Key, c.Value}
		})(parsedAuthJson.Bearer),
		Basic: fp.Map(func(c CredentialJson) struct{ Key, Value string } {
			return struct{ Key, Value string }{c.Key, c.Value}
		})(parsedAuthJson.Basic),
		OAuth2: fp.Map(func(c CredentialJson) struct{ Key, Value string } {
			return struct{ Key, Value string }{c.Key, c.Value}
		})(parsedAuthJson.OAuth2),
	}
}

func GetWorkspaceFromJsonBytes(bytes []byte) (PostmanWorkspace, error) {
	// TODO - Implement
	return PostmanWorkspace{}, nil
}

func GetEnvironmentFromJsonBytes(bytes []byte) (PostmanEnvironment, error) {
	// TODO - Implement
	return PostmanEnvironment{}, nil
}
