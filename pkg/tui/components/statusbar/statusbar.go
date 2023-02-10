package statusbar

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/soft-serve/ui/common"
	"github.com/muesli/reflow/truncate"
)

// StatusBarMsg is a message sent to the status bar.
type StatusBarMsg struct {
	Key    string
	Value  string
	Info   string
	Branch string
}

// StatusBar is a status bar model.
type StatusBar struct {
	common common.Common
	msg    StatusBarMsg
}

// Model is an interface that supports setting the status bar information.
type Model interface {
	StatusBarValue() string
	StatusBarInfo() string
}

// New creates a new status bar component.
func New(c common.Common) *StatusBar {
	s := &StatusBar{
		common: c,
	}
	return s
}

// SetSize implements common.Component.
func (s *StatusBar) SetSize(width, height int) {
	s.common.Width = width
	s.common.Height = height
}

// Init implements tea.Model.
func (s *StatusBar) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (s *StatusBar) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case StatusBarMsg:
		s.msg = msg
	}
	return s, nil
}

// View implements tea.Model.
func (s *StatusBar) View() string {
	st := s.common.Styles
	w := lipgloss.Width
	help := s.common.Zone.Mark(
		"repo-help",
		st.StatusBarHelp.Render("? Help"),
	)
	key := st.StatusBarKey.Render(s.msg.Key)
	info := ""
	if s.msg.Info != "" {
		info = st.StatusBarInfo.Render(s.msg.Info)
	}
	branch := st.StatusBarBranch.Render(s.msg.Branch)
	maxWidth := s.common.Width - w(key) - w(info) - w(branch) - w(help)
	v := truncate.StringWithTail(s.msg.Value, uint(maxWidth-st.StatusBarValue.GetHorizontalFrameSize()), "…")
	value := st.StatusBarValue.
		Width(maxWidth).
		Render(v)

	return lipgloss.NewStyle().MaxWidth(s.common.Width).
		Render(
			lipgloss.JoinHorizontal(lipgloss.Top,
				key,
				value,
				info,
				branch,
				help,
			),
		)
}
