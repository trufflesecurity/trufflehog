package source_configure

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type truffleCmdModel struct {
	textinputs.Model
}

func GetTrufflehogConfiguration() truffleCmdModel {
	verification := textinputs.InputConfig{
		Label:       "Skip Verification",
		Key:         "no-verification",
		Required:    false,
		Help:        "Check if a suspected secret is real or not",
		Placeholder: "false",
	}

	verifiedResults := textinputs.InputConfig{
		Label:       "Verified results",
		Key:         "only-verified",
		Required:    false,
		Help:        "Return only verified results",
		Placeholder: "false",
	}

	jsonOutput := textinputs.InputConfig{
		Label:       "JSON output",
		Key:         "json",
		Required:    false,
		Help:        "Output results to JSON",
		Placeholder: "false",
	}

	excludeDetectors := textinputs.InputConfig{
		Label:       "Exclude detectors",
		Key:         "exclude_detectors",
		Required:    false,
		Help:        "Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.",
		Placeholder: "",
	}

	concurrency := textinputs.InputConfig{
		Label:       "Concurrency",
		Key:         "concurrency",
		Required:    false,
		Help:        "Number of concurrent workers.",
		Placeholder: "1",
	}

	return truffleCmdModel{textinputs.New([]textinputs.InputConfig{jsonOutput, verification, verifiedResults, excludeDetectors, concurrency}).SetSkip(true)}
}

func (m truffleCmdModel) GetFlags() string {
	var command []string
	inputs := m.GetInputs()

	if isTrue(inputs["json"]) {
		command = append(command, "--json")
	}

	if isTrue(inputs["no-verification"]) {
		command = append(command, "--no-verification")
	}

	if isTrue(inputs["only-verified"]) {
		command = append(command, "--only-verified")
	}

	if inputs["exclude_detectors"] != "" {
		cmd := "--exclude-detectors=" + strings.ReplaceAll(inputs["exclude_detectors"], " ", "")
		command = append(command, cmd)
	}

	if inputs["concurrency"] != "" {
		command = append(command, "--concurrency="+inputs["concurrency"])
	}

	return strings.Join(command, " ")
}

func isTrue(val string) bool {
	value := strings.ToLower(val)
	if value == "true" || value == "yes" || value == "y" || value == "1" {
		return true
	}
	return false
}
