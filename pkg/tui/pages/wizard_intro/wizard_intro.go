package wizard_intro

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/selector"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

var (
	wizardIntroChoices = []string{
		"Scan a source using wizard",
		"Scan a source with config",
		"View open-source project",
		"Inquire about Trufflehog Enterprise",
		"Quit",
	}
)

type WizardIntro struct {
	common.Common
	cursor   int
	action   string
	selector *selector.Selector
}

func New(cmn common.Common) *WizardIntro {
	sel := selector.New(cmn,
		[]selector.IdentifiableItem{},
		ItemDelegate{&cmn})

	return &WizardIntro{Common: cmn, selector: sel}
}

func (m *WizardIntro) Init() tea.Cmd {
	m.selector.Select(0)
	return nil
}

func (m *WizardIntro) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0)

	s, cmd := m.selector.Update(msg)
	m.selector = s.(*selector.Selector)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *WizardIntro) View() string {
	s := strings.Builder{}
	s.WriteString("What do you want to do?\n\n")

	return m.selector.View()

	for i := 0; i < len(wizardIntroChoices); i++ {
		if m.cursor == i {
			selectedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(styles.Colors["sprout"]))
			s.WriteString(selectedStyle.Render(" (•) " + wizardIntroChoices[i]))
		} else {
			s.WriteString(" ( ) " + wizardIntroChoices[i])
		}

		s.WriteString("\n")
	}

	return styles.AppStyle.Render(s.String())
}

func (m *WizardIntro) ShortHelp() []key.Binding {
	kb := make([]key.Binding, 0)
	kb = append(kb,
		m.Common.KeyMap.UpDown,
		m.Common.KeyMap.Section,
	)
	return kb
}

func (m *WizardIntro) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
