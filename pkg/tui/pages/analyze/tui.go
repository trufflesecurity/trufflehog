package analyze

import (
	"errors"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type Analyze struct {
	common.Common
	viewed     bool
	model      tea.Model
	keyType    string
	secretInfo *SecretInfo
	args       []string
}

type SecretInfo struct {
	Parts map[string]string
	Cfg   *config.Config
}

var AbortError error = errors.New("command aborted")

func New(c common.Common, args []string) *Analyze {
	return &Analyze{Common: c, viewed: false, args: args}
}

func (ui *Analyze) Init() tea.Cmd {
	return nil
}

// todo -- remove
// func Run(keyType string) (string, *SecretInfo, error) {
// 	// If a keyType is provided, make sure it's in the list of AvailableAnalyzers.
// 	if keyType != "" {
// 		var found bool
// 		for _, a := range analyzers.AvailableAnalyzers {
// 			if strings.EqualFold(a, keyType) {
// 				keyType = a
// 				found = true
// 				break
// 			}
// 		}
// 		if !found {
// 			return "", nil, fmt.Errorf("Unrecognized command %q", keyType)
// 		}
// 	}

// 	t := &TUI{
// 		keyType: keyType,
// 		common: &common.Common{
// 			KeyMap: keymap.DefaultKeyMap(),
// 		},
// 	}
// 	if _, err := tea.NewProgram(t).Run(); err != nil {
// 		return "", nil, err
// 	}
// 	if t.secretInfo == nil {
// 		return "", nil, AbortError
// 	}
// 	return t.keyType, t.secretInfo, nil
// }

func (ui *Analyze) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Always be able to force quit.
	if msg, ok := msg.(tea.KeyMsg); ok && msg.Type.String() == "ctrl+c" {
		return ui, tea.Quit
	}

	switch m := msg.(type) {
	case SetKeyTypeMsg:
		ui.keyType = string(m)
	case SecretInfo:
		ui.secretInfo = &m
		return ui, tea.Quit
	}

	if ui.model == nil {
		return ui, nil
	}

	var cmd tea.Cmd
	ui.model, cmd = ui.model.Update(msg)
	return ui, cmd
}

func (ui *Analyze) View() string {
	if ui.model == nil {
		return "Loading..."
	}

	return ui.model.View()
}

func (ui *Analyze) SetSize(width, height int) {
	h, v := styles.AppStyle.GetFrameSize()
	h, v = width-h, height-v
	ui.Common.SetSize(h, v)

	if ui.model != nil {
		return
	}

	// Set the model only after we have size information.
	// TODO: Responsive pages.
	ui.model = NewKeyTypePage(&ui.Common)
	if len(ui.args) > 0 {
		ui.model = NewFormPage(&ui.Common, ui.args[0])
	}

	// if ui.keyType == "" {
	// 	ui.model = NewKeyTypePage(&ui.Common)
	// } else {
	// 	ui.model = NewFormPage(&ui.Common, ui.keyType)
	// }
}

type SetKeyTypeMsg string

func SetKeyTypeCmd(keyType string) tea.Cmd {
	return func() tea.Msg {
		return SetKeyTypeMsg(keyType)
	}
}

func (m *Analyze) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *Analyze) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
