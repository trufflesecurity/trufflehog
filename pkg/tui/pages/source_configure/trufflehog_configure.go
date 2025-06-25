package source_configure

import (
	"runtime"
	"strconv"
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
		Placeholder: strconv.Itoa(runtime.NumCPU()),
	}

	return truffleCmdModel{textinputs.New([]textinputs.InputConfig{jsonOutput, verification, verifiedResults, excludeDetectors, concurrency}).SetSkip(true)}
}

func (m truffleCmdModel) Cmd() string {
	var command []string
	inputs := m.GetInputs()

	if isTrue(inputs["json"].Value) {
		command = append(command, "--json")
	}

	if isTrue(inputs["no-verification"].Value) {
		command = append(command, "--no-verification")
	}

	if isTrue(inputs["only-verified"].Value) {
		command = append(command, "--results=verified")
	}

	if inputs["exclude_detectors"].Value != "" {
		cmd := "--exclude-detectors=" + strings.ReplaceAll(inputs["exclude_detectors"].Value, " ", "")
		command = append(command, cmd)
	}

	if inputs["concurrency"].Value != "" {
		command = append(command, "--concurrency="+inputs["concurrency"].Value)
	}

	return strings.Join(command, " ")
}

func (m truffleCmdModel) Summary() string {
	summary := strings.Builder{}
	keys := []string{"no-verification", "only-verified", "json", "exclude_detectors", "concurrency"}

	inputs := m.GetInputs()
	labels := m.GetLabels()
	for _, key := range keys {
		if inputs[key].Value != "" {
			summary.WriteString("\t" + labels[key] + ": " + inputs[key].Value + "\n")
		}
	}

	if summary.Len() == 0 {
		summary.WriteString("\tRunning with defaults\n")

	}

	summary.WriteString("\n")
	return summary.String()
}

func isTrue(val string) bool {
	value := strings.ToLower(val)
	isTrue, _ := strconv.ParseBool(value)

	if isTrue || value == "yes" || value == "y" {
		return true
	}
	return false
}
