package tui

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/keymap"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

// TUI is the main TUI model.
type TUI struct {
	keyType    string
	secretInfo *SecretInfo
	common     *common.Common
	model      tea.Model
}

type SecretInfo struct {
	Parts map[string]string
	Cfg   *config.Config
}

var AbortError error = errors.New("command aborted")

func Run(keyType string) (string, *SecretInfo, error) {
	// If a keyType is provided, make sure it's in the list of AvailableAnalyzers.
	if keyType != "" {
		var found bool
		for _, a := range analyzers.AvailableAnalyzers() {
			if strings.EqualFold(a, keyType) {
				keyType = a
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("Unrecognized command %q", keyType)
		}
	}

	t := &TUI{
		keyType: keyType,
		common: &common.Common{
			KeyMap: keymap.DefaultKeyMap(),
		},
	}
	if _, err := tea.NewProgram(t).Run(); err != nil {
		return "", nil, err
	}
	if t.secretInfo == nil {
		return "", nil, AbortError
	}
	return t.keyType, t.secretInfo, nil
}

func (ui *TUI) Init() tea.Cmd {
	return nil
}

func (ui *TUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		ui.SetSize(msg)
	}
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

func (ui *TUI) View() string {
	if ui.model == nil {
		return "Loading..."
	}
	return ui.model.View()
}

func (ui *TUI) SetSize(msg tea.WindowSizeMsg) {
	h, v := styles.AppStyle.GetFrameSize()
	h, v = msg.Width-h, msg.Height-v
	ui.common.SetSize(h, v)
	if ui.model != nil {
		return
	}

	// Set the model only after we have size information.
	// TODO: Responsive pages.
	if ui.keyType == "" {
		ui.model = NewKeyTypePage(ui.common)
	} else {
		ui.model = NewFormPage(ui.common, ui.keyType)
	}
}

type SetKeyTypeMsg string

func SetKeyTypeCmd(keyType string) tea.Cmd {
	return func() tea.Msg {
		return SetKeyTypeMsg(keyType)
	}
}
