package elasticsearch

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type elasticSearchCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "To connect to a local cluster, please provide the node IPs and either (username AND password) OR service token. ⭐\n⭐ To connect to a cloud cluster, please provide cloud ID AND API key."
}

func GetFields() elasticSearchCmdModel {
	return elasticSearchCmdModel{textinputs.New([]textinputs.InputConfig{
		{
			Label:    "Elastic node(s)",
			Key:      "nodes",
			Required: false,
			Help:     "Elastic node IPs - for scanning local clusters. Separate by space if multiple.",
		},
		{
			Label:    "Username",
			Key:      "username",
			Required: false,
			Help:     "Elasticsearch username. Pairs with password. For scanning local clusters.",
		},
		{
			Label:    "Password",
			Key:      "password",
			Required: false,
			Help:     "Elasticsearch password. Pairs with username. For scanning local clusters.",
		},
		{
			Label:    "Service Token",
			Key:      "serviceToken",
			Required: false,
			Help:     "Elastic service token. For scanning local clusters.",
		},
		{
			Label:    "Cloud ID",
			Key:      "cloudId",
			Required: false,
			Help:     "Elastic cloud ID. Pairs with API key. For scanning cloud clusters.",
		},
		{
			Label:    "API Key",
			Key:      "apiKey",
			Required: false,
			Help:     "Elastic API key. Pairs with cloud ID. For scanning cloud clusters.",
		}})}
}

func findFirstNonEmptyKey(inputs map[string]textinputs.Input, keys []string) string {
	for _, key := range keys {
		if val, ok := inputs[key]; ok && val.Value != "" {
			return key
		}
	}
	return ""
}

func getConnectionKeys(inputs map[string]textinputs.Input) []string {
	keys := []string{"username", "password", "serviceToken", "cloudId", "apiKey"}
	key := findFirstNonEmptyKey(inputs, keys)

	keyMap := map[string][]string{
		"username":     {"username", "password", "nodes"},
		"password":     {"username", "password", "nodes"},
		"serviceToken": {"serviceToken", "nodes"},
		"cloudId":      {"cloudId", "apiKey"},
		"apiKey":       {"cloudId", "apiKey"},
	}

	if val, ok := keyMap[key]; ok {
		return val
	}

	return nil
}

func (m elasticSearchCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "elasticsearch")
	inputs := m.GetInputs()

	for _, key := range getConnectionKeys(inputs) {
		val, ok := inputs[key]
		if !ok || val.Value == "" {
			continue
		}

		if key == "nodes" {
			nodes := strings.Fields(val.Value)
			for _, node := range nodes {
				command = append(command, "--nodes="+node)
			}
		} else {
			command = append(command, "--"+key+"="+val.Value)
		}
	}

	return strings.Join(command, " ")
}

func (m elasticSearchCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	summaryKeys := getConnectionKeys(inputs)
	return common.SummarizeSource(summaryKeys, inputs, labels)
}
