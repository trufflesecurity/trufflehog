package source_configure

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
)

/*
OUTPUT
- Command line text
- JSON output	(--json)

SWITCH 1: Verification
- Verify things (default)
- Skip verification (--no-verification)

SWITCH 2: Print results
- all results found (default)
- all verified results found (--only-verified)

numberical options
- concurrency
- archive_max_size
- archive_max_depth
- archive_timeout

string options
- include-detectors
- exclude-detectors
*/

type TrufflehogComponent struct {
	common.Common
}

func NewTrufflehogComponent(common common.Common) *TrufflehogComponent {
	return &TrufflehogComponent{
		Common: common,
	}
}

func (m *TrufflehogComponent) Init() tea.Cmd {
	return nil
}

func (m *TrufflehogComponent) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

func (m *TrufflehogComponent) View() string {
	return "trufflehog configure component"
}

func (m *TrufflehogComponent) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *TrufflehogComponent) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
