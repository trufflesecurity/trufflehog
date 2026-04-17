package source_configure

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

// SetArgsMsg carries the final argv the parent TUI will re-exec TruffleHog
// with. It is a string slice so values with spaces (filesystem paths, etc.)
// survive without shell quoting.
type SetArgsMsg []string

type RunComponent struct {
	common.Common
	parent          *SourceConfigure
	reviewList      list.Model
	reviewListItems []list.Item
}

func NewRunComponent(common common.Common, parent *SourceConfigure) *RunComponent {
	// Make list of SourceItems.
	listItems := []list.Item{
		Item{title: "🔎 Source configuration"},
		Item{title: "🐽 TruffleHog configuration"},
		Item{title: "💸 Sales pitch", description: "\tContinuous monitoring, state tracking, remediations, and more\n\t🔗 https://trufflesecurity.com/trufflehog"},
	}

	// Setup list
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle.Foreground(lipgloss.Color("white"))
	delegate.Styles.SelectedDesc.Foreground(lipgloss.Color("white"))
	delegate.SetHeight(3)

	reviewList := list.New(listItems, delegate, common.Width, common.Height)

	reviewList.SetShowTitle(false)
	reviewList.SetShowStatusBar(false)
	reviewList.SetFilteringEnabled(false)

	return &RunComponent{
		Common:          common,
		parent:          parent,
		reviewList:      reviewList,
		reviewListItems: listItems,
	}
}

func (m *RunComponent) Init() tea.Cmd {
	return nil
}

func (m *RunComponent) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := styles.AppStyle.GetFrameSize()
		m.reviewList.SetSize(msg.Width-h, msg.Height/2-v)
	case tea.KeyMsg:
		if msg.Type == tea.KeyEnter {
			args := buildCommand(m.parent.sourceFields, m.parent.truffleFields)
			cmd := func() tea.Msg { return SetArgsMsg(args) }
			return m, cmd
		}
	}
	if len(m.reviewListItems) > 0 && m.parent != nil && m.parent.sourceFields != nil {
		m.reviewListItems[0] = m.reviewListItems[0].(Item).SetDescription(m.parent.sourceFields.Summary())
		m.reviewListItems[1] = m.reviewListItems[1].(Item).SetDescription(m.parent.truffleFields.Summary())
	}
	var cmd tea.Cmd
	m.reviewList, cmd = m.reviewList.Update(msg)
	return m, tea.Batch(cmd)
}

func (m *RunComponent) View() string {
	var view strings.Builder

	view.WriteString("\n🔎 Source configuration\n")
	view.WriteString(m.parent.sourceFields.Summary())

	view.WriteString("\n🐽 TruffleHog configuration\n")
	view.WriteString(m.parent.truffleFields.Summary())

	view.WriteString("\n💸 Sales pitch\n")
	view.WriteString("\tContinuous monitoring, state tracking, remediations, and more\n")
	view.WriteString("\t🔗 https://trufflesecurity.com/trufflehog\n\n")

	view.WriteString(styles.BoldTextStyle.Render("\n\n🐷 Run TruffleHog for "+m.parent.configTabSource) + " 🐷\n\n")

	view.WriteString("Generated TruffleHog command\n")
	view.WriteString(styles.HintTextStyle.Render("Save this if you want to run it again later!") + "\n")

	args := buildCommand(m.parent.sourceFields, m.parent.truffleFields)
	view.WriteString(styles.CodeTextStyle.Render(renderCommand(args)))

	focusedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	view.WriteString("\n\n" + focusedStyle.Render("[ Run TruffleHog ]") + "\n\n")

	// view.WriteString(m.reviewList.View())
	return view.String()
}

// buildCommand concatenates the source-specific args with the TruffleHog-wide
// args. It tolerates nil adapters so the review tab renders even before a
// source is selected.
func buildCommand(source, truffle sources.CmdModel) []string {
	var out []string
	if source != nil {
		out = append(out, source.Cmd()...)
	}
	if truffle != nil {
		out = append(out, truffle.Cmd()...)
	}
	return out
}

// renderCommand joins argv with spaces for display only. Tokens that contain
// spaces get wrapped in single quotes so users can copy/paste the result.
func renderCommand(args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, "trufflehog")
	for _, a := range args {
		if strings.ContainsAny(a, " \t") {
			parts = append(parts, "'"+a+"'")
			continue
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

func (m *RunComponent) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *RunComponent) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
