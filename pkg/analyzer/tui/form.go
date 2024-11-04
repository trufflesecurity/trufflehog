package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
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
	var inputs []textinputs.InputConfig
	switch strings.ToLower(keyType) {
	case "twilio":
		inputs = []textinputs.InputConfig{{
			Label:    "SID",
			Key:      "sid",
			Required: true,
		}, {
			Label:       "Token",
			Key:         "key",
			Required:    true,
			RedactInput: true,
		}}
	case "shopify":
		inputs = []textinputs.InputConfig{{
			Label:       "Secret",
			Key:         "key",
			Required:    true,
			RedactInput: true,
		}, {
			Label:    "Shopify URL",
			Key:      "url",
			Required: true,
		}}
	default:
		inputs = []textinputs.InputConfig{{
			Label:       "Secret",
			Key:         "key",
			Required:    true,
			RedactInput: true,
		}}
	}

	// Always append a log file option.
	inputs = append(inputs, textinputs.InputConfig{
		Label: "Log file",
		Help:  "Log HTTP requests that analysis performs to this file",
		Key:   "log_file",
	})

	form := textinputs.New(inputs).
		SetHeader(titleStyle.Render(fmt.Sprintf("Configuring %s analyzer", keyType))).
		SetFooter("⚠️  Running TruffleHog Analyze will send a lot of requests ⚠️\n\n🚧 Please confirm you have permission to run TruffleHog Analyze against this secret 🚧").
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
			logFile := values["log_file"]
			cfg := config.Config{
				LogFile:        logFile,
				LoggingEnabled: logFile != "",
			}
			return SecretInfo{Cfg: &cfg, Parts: values}
		}
		return nil, secretInfoCmd
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
	index, ok := slices.BinarySearch(analyzers.AvailableAnalyzers(), ui.KeyType)
	if !ok {
		// Should be impossible.
		index = 0
	}
	page.list.Select(index)
	return page, nil
}
