package tui

import (
	"errors"
	"fmt"
	"slices"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/keymap"
)

// TUI is the main TUI model.
type TUI struct {
	keyType    string
	secretInfo SecretInfo
	common     common.Common
	model      tea.Model
	abort      bool
}

type SecretInfo struct {
	Parts map[string]string
	Cfg   *config.Config
}

var AbortError error = errors.New("command aborted")

func Run(keyType string) (string, *SecretInfo, error) {
	// If a keyType is provided, make sure it's in the list of AvailableAnalyzers.
	if keyType != "" {
		if _, ok := slices.BinarySearch(analyzers.AvailableAnalyzers, keyType); !ok {
			return "", nil, fmt.Errorf("Unrecognized command %q", keyType)
		}
	}

	t := &TUI{
		keyType: keyType,
		common: common.Common{
			KeyMap: keymap.DefaultKeyMap(),
		},
	}
	if _, err := tea.NewProgram(t).Run(); err != nil {
		return "", nil, err
	}
	if t.abort {
		return "", nil, AbortError
	}
	return t.keyType, &t.secretInfo, nil
}

func (ui *TUI) Init() tea.Cmd {
	if ui.keyType == "" {
		ui.model = KeyTypePage{Common: ui.common}
	} else {
		ui.model = FormPage{Common: ui.common, KeyType: ui.keyType}
	}
	return nil
}

func (ui *TUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		ui.SetSize(msg)
		return ui, nil
	}
	// Always be able to force quit.
	if msg, ok := msg.(tea.KeyMsg); ok && msg.Type.String() == "ctrl+c" {
		ui.abort = true
		return ui, tea.Quit
	}

	switch m := msg.(type) {
	case SetKeyTypeMsg:
		ui.keyType = string(m)
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
	ui.common.SetSize(msg.Width, msg.Height)
	if ui.model != nil {
		ui.model, _ = ui.model.Update(msg)
	}
}

type SetKeyTypeMsg string

func SetKeyTypeCmd(keyType string) tea.Cmd {
	return func() tea.Msg {
		return SetKeyTypeMsg(keyType)
	}
}
