package tui

import (
	"fmt"
	"slices"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type FormPage struct {
	Common  *common.Common
	KeyType string
	form    textinputs.Model
}

func NewFormPage(c *common.Common, keyType string) FormPage {
	inputs := []textinputs.InputConfig{{
		Label:       "Secret",
		Key:         "key",
		Required:    true,
		RedactInput: true,
	}}
	if keyType == "shopify" {
		inputs = append(inputs, textinputs.InputConfig{
			Label:    "Shopify URL",
			Key:      "url",
			Required: true,
		})
	}

	form := textinputs.New(inputs).
		SetHeader(titleStyle.Render(fmt.Sprintf("Configuring %s analyzer", keyType))).
		SetFooter("⚠️  Running TruffleHog Analyze will send a lot of requests ⚠️").
		SetSubmitMsg("Run TruffleHog Analyze")
	return FormPage{
		Common:  c,
		KeyType: keyType,
		form:    form,
	}
}

func (FormPage) Init() tea.Cmd {
	return nil
}

func (ui FormPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// TODO: Check form focus.
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, ui.Common.KeyMap.Back):
			return ui.PrevPage()
		}
	}
	if _, ok := msg.(textinputs.SelectNextMsg); ok {
		values := make(map[string]string)
		for k, v := range ui.form.GetInputs() {
			values[k] = v.Value
		}
		secretInfoCmd := func() tea.Msg {
			// TODO: Set Config
			return SecretInfo{Parts: values}
		}
		return nil, tea.Batch(tea.Quit, secretInfoCmd)
	}
	form, cmd := ui.form.Update(msg)
	ui.form = form.(textinputs.Model)
	return ui, cmd
}

func (ui FormPage) View() string {
	return styles.AppStyle.Render(ui.form.View())
}

func (ui FormPage) PrevPage() (tea.Model, tea.Cmd) {
	page := NewKeyTypePage(ui.Common)
	// Select what was previously selected.
	index, ok := slices.BinarySearch(analyzers.AvailableAnalyzers, ui.KeyType)
	if !ok {
		// Should be impossible.
		index = 0
	}
	page.list.Select(index)
	return page, nil
}
