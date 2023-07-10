package source_configure

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetTrufflehogConfiguration() tea.Model {
	verification := textinputs.InputConfig{
		Label:       "Verification",
		Required:    false,
		Help:        "Check if a suspected secret is real or not",
		Placeholder: "true",
	}

	verifiedResults := textinputs.InputConfig{
		Label:       "Verified results",
		Required:    false,
		Help:        "Return only verified results",
		Placeholder: "false",
	}

	jsonOutput := textinputs.InputConfig{
		Required:    false,
		Label:       "JSON output",
		Help:        "Output results to JSON",
		Placeholder: "false",
	}

	excludeDetectors := textinputs.InputConfig{
		Label:       "Exclude detectors",
		Required:    false,
		Help:        "Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.",
		Placeholder: "",
	}

	concurrency := textinputs.InputConfig{
		Label:       "Concurrency",
		Required:    false,
		Help:        "Number of concurrent workers.",
		Placeholder: "1",
	}

	return textinputs.New([]textinputs.InputConfig{jsonOutput, verification, verifiedResults, excludeDetectors, concurrency}).SetSkip(true)
}
