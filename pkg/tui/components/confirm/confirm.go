package confirm

import (
	"fmt"
	"unicode"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
)

type Confirm struct {
	common            common.Common
	message           string
	affirmativeChoice string
	negativeChoice    string
	affirmativeUpdate func() (tea.Model, tea.Cmd)
	negativeUpdate    func() (tea.Model, tea.Cmd)
	choice            bool
}

type Msg struct {
	Choice  bool
	Message string
}

type ConfirmOpt func(*Confirm)

func WithAffirmativeMessage(msg string) ConfirmOpt {
	return func(c *Confirm) { c.affirmativeChoice = msg }
}

func WithNegativeMessage(msg string) ConfirmOpt {
	return func(c *Confirm) { c.negativeChoice = msg }
}

func WithDefault(choice bool) ConfirmOpt {
	return func(c *Confirm) { c.choice = choice }
}

func WithAffirmativeTransition(m tea.Model, cmd tea.Cmd) ConfirmOpt {
	return func(c *Confirm) {
		c.affirmativeUpdate = func() (tea.Model, tea.Cmd) {
			return m, cmd
		}
	}
}

func WithNegativeTransition(m tea.Model, cmd tea.Cmd) ConfirmOpt {
	return func(c *Confirm) {
		c.negativeUpdate = func() (tea.Model, tea.Cmd) {
			return m, cmd
		}
	}
}

func New(c common.Common, msg string, opts ...ConfirmOpt) Confirm {
	confirm := Confirm{
		common:            c,
		message:           msg,
		affirmativeChoice: "Yes",
		negativeChoice:    "Cancel",
		affirmativeUpdate: func() (tea.Model, tea.Cmd) { return nil, nil },
		negativeUpdate:    func() (tea.Model, tea.Cmd) { return nil, nil },
	}
	for _, opt := range opts {
		opt(&confirm)
	}
	return confirm
}

func (Confirm) Init() tea.Cmd {
	return nil
}

func (c Confirm) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return c, nil
	}
	switch {
	case key.Matches(keyMsg, c.common.KeyMap.Left) || keyMatchesFirstChar(keyMsg, c.negativeChoice):
		c.choice = false
	case key.Matches(keyMsg, c.common.KeyMap.Right) || keyMatchesFirstChar(keyMsg, c.affirmativeChoice):
		c.choice = true
	case key.Matches(keyMsg, c.common.KeyMap.Select):
		model, cmd := c.negativeUpdate()
		if c.choice {
			model, cmd = c.affirmativeUpdate()
		}

		return model, cmd
	}
	return c, nil
}

func (c Confirm) View() string {
	var affirmative, negative string
	if c.choice {
		affirmative = fmt.Sprintf("[ %s ]", c.affirmativeChoice)
		negative = fmt.Sprintf("  %s  ", c.negativeChoice)
	} else {
		affirmative = fmt.Sprintf("  %s  ", c.affirmativeChoice)
		negative = fmt.Sprintf("[ %s ]", c.negativeChoice)
	}
	return fmt.Sprintf("%s\t%s\t%s", c.message, negative, affirmative)
}

func keyMatchesFirstChar(msg tea.KeyMsg, s string) bool {
	if s == "" {
		return false
	}
	firstChar := rune(s[0])
	return msg.String() == string(unicode.ToLower(firstChar))
}
