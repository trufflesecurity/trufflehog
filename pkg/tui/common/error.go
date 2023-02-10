package common

import tea "github.com/charmbracelet/bubbletea"

// ErrorMsg is a Bubble Tea message that represents an error.
type ErrorMsg error

// ErrorCmd returns an ErrorMsg from error.
func ErrorCmd(err error) tea.Cmd {
	return func() tea.Msg {
		return ErrorMsg(err)
	}
}
