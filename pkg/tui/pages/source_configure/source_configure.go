package source_configure

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
	"gopkg.in/alecthomas/kingpin.v2"
)

type SourceConfigure struct {
	common.Common
	cmd         *kingpin.CmdModel
	inputs      []textinput.Model
	inputsTitle []string
	focused     int
	err         error
}

func (m SourceConfigure) Init() tea.Cmd {
	return nil
}

var (
	labelPrimaryStyle = lipgloss.NewStyle().Foreground(
		lipgloss.Color(styles.Colors["sprout"]))
)

func New(c common.Common) *SourceConfigure {
	return &SourceConfigure{
		Common:      c,
		cmd:         nil,
		inputs:      nil,
		inputsTitle: nil,
		focused:     0,
		err:         nil,
	}
}

func (m *SourceConfigure) SetCmd(cmd *kingpin.CmdModel) {
	numInputs := len(cmd.Args) + len(cmd.Flags)
	var inputs []textinput.Model = make([]textinput.Model, 0, numInputs)
	var inputsTitle []string = make([]string, 0, numInputs)

	for _, arg := range cmd.Args {
		in := textinput.New()
		in.Placeholder = arg.Name
		in.CharLimit = 50
		in.Width = 30
		in.Prompt = ""

		inputs = append(inputs, in)
		if arg.Required {
			inputsTitle = append(inputsTitle, arg.Name+"*")
		} else {
			inputsTitle = append(inputsTitle, arg.Name)
		}
	}

	for _, flag := range cmd.Flags {
		in := textinput.New()
		in.Placeholder = flag.Name
		in.CharLimit = 50
		in.Width = 30
		in.Prompt = ""

		inputs = append(inputs, in)
		if flag.Required {
			inputsTitle = append(inputsTitle, flag.Name+"*")
		} else {
			inputsTitle = append(inputsTitle, flag.Name)
		}
	}
	inputs[0].Focus()
}

func (m *SourceConfigure) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd = make([]tea.Cmd, len(m.inputs))

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			if m.focused == len(m.inputs)-1 {
				return m, tea.Quit
			}
			m.nextInput()
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyShiftTab, tea.KeyCtrlP:
			m.prevInput()
		case tea.KeyTab, tea.KeyCtrlN:
			m.nextInput()
		}
		for i := range m.inputs {
			m.inputs[i].Blur()
		}
		m.inputs[m.focused].Focus()
	}

	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m *SourceConfigure) nextInput() {
	m.focused = (m.focused + 1) % len(m.inputs)
}

func (m *SourceConfigure) prevInput() {
	m.focused--
	// Wrap around
	if m.focused < 0 {
		m.focused = len(m.inputs) - 1
	}
}

func (m *SourceConfigure) View() string {
	var views []string = make([]string, 0, len(m.inputs))

	for i, input := range m.inputs {
		view := fmt.Sprintf(
			`%s
%s`,
			labelPrimaryStyle.Width(30).Render(m.inputsTitle[i]),
			input.View(),
		)
		views = append(views, view)
	}

	return strings.Join(views, "\n\n")
}

func (m *SourceConfigure) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *SourceConfigure) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}

func newSourceConfigure(cmd *kingpin.CmdModel) *SourceConfigure {
	numInputs := len(cmd.Args) + len(cmd.Flags)
	var inputs []textinput.Model = make([]textinput.Model, 0, numInputs)
	var inputsTitle []string = make([]string, 0, numInputs)

	for _, arg := range cmd.Args {
		in := textinput.New()
		in.Placeholder = arg.Name
		in.CharLimit = 50
		in.Width = 30
		in.Prompt = ""

		inputs = append(inputs, in)
		if arg.Required {
			inputsTitle = append(inputsTitle, arg.Name+"*")
		} else {
			inputsTitle = append(inputsTitle, arg.Name)
		}
	}

	for _, flag := range cmd.Flags {
		in := textinput.New()
		in.Placeholder = flag.Name
		in.CharLimit = 50
		in.Width = 30
		in.Prompt = ""

		inputs = append(inputs, in)
		if flag.Required {
			inputsTitle = append(inputsTitle, flag.Name+"*")
		} else {
			inputsTitle = append(inputsTitle, flag.Name)
		}
	}

	inputs[0].Focus()
	return &SourceConfigure{
		inputs:      inputs,
		inputsTitle: inputsTitle,
		focused:     0,
		err:         nil,
	}
}
