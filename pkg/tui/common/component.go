package common

import (
	"github.com/charmbracelet/bubbles/help"
	tea "github.com/charmbracelet/bubbletea"
)

// Component represents a Bubble Tea model that implements a SetSize function.
type Component interface {
	tea.Model
	help.KeyMap
	SetSize(width, height int)
}
