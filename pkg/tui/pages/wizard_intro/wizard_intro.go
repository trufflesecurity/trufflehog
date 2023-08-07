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

const (
	ScanSourceWithWizard Item = iota
	// ScanSourceWithConfig
	ViewHelpDocs
	ViewOSSProject
	EnterpriseInquire
	Quit
)

func (w Item) String() string {
	switch w {
	case ScanSourceWithWizard:
		return "Scan a source using wizard"
	//case ScanSourceWithConfig:
	//	return "Scan a source with a config file"
	case ViewHelpDocs:
		return "View help docs"
	case ViewOSSProject:
		return "View open-source project"
	case EnterpriseInquire:
		return "Inquire about TruffleHog Enterprise"
	case Quit:
		return "Quit"
	}
	panic("unreachable")
}

type WizardIntro struct {
	common.Common
	selector *selector.Selector
}

func New(cmn common.Common) *WizardIntro {
	sel := selector.New(cmn,
		[]selector.IdentifiableItem{
			ScanSourceWithWizard,
			// ScanSourceWithConfig,
			ViewHelpDocs,
			ViewOSSProject,
			EnterpriseInquire,
			Quit,
		},
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

	for i, selectorItem := range m.selector.Items() {
		// Cast the interface to the concrete Item struct.
		item := selectorItem.(Item)
		if m.selector.Index() == i {
			selectedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(styles.Colors["sprout"]))
			s.WriteString(selectedStyle.Render(" (•) " + item.Title()))
		} else {
			s.WriteString(" ( ) " + item.Title())
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
