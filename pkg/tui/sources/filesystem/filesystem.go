package filesystem

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type fsModel struct {
	textinputs.Model
}

func GetFields() fsModel {
	path := textinputs.InputConfig{
		Label:       "Path",
		Key:         "path",
		Required:    true,
		Help:        "Files and directories to scan. Separate by space if multiple.",
		Placeholder: "path/to/file.txt path/to/another/dir",
	}

	return fsModel{textinputs.New([]textinputs.InputConfig{path})}
}

func (m fsModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "filesystem")

	inputs := m.GetInputs()
	command = append(command, inputs["path"].Value)

	return strings.Join(command, " ")
}

func (m fsModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"path"}
	return common.SummarizeSource(keys, inputs, labels)
}
