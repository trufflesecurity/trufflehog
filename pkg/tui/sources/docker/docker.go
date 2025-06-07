package docker

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type dockerCmdModel struct {
	textinputs.Model
}

func GetFields() dockerCmdModel {
	images := textinputs.InputConfig{
		Label:       "Docker image(s)",
		Key:         "images",
		Required:    true,
		Help:        "Separate by space if multiple.",
		Placeholder: "trufflesecurity/secrets",
	}

	return dockerCmdModel{textinputs.New([]textinputs.InputConfig{images})}
}

func (m dockerCmdModel) Cmd() string {

	var command []string
	command = append(command, "trufflehog", "docker")

	inputs := m.GetInputs()
	vals := inputs["images"].Value

	if vals != "" {
		images := strings.Fields(vals)
		for _, image := range images {
			command = append(command, "--image="+image)
		}
	}

	return strings.Join(command, " ")
}

func (m dockerCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()
	keys := []string{"images"}

	return common.SummarizeSource(keys, inputs, labels)
}
