// Package tui is the thin runner that boots the Bubble Tea program, wires
// up the router and page factories, and hands the final deliverables back
// to main (argv for kingpin, or an analyzer SecretInfo).
package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	analyzerform "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/analyzer-form"
	analyzerpicker "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/analyzer-picker"
	linkcard "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/link-card"
	sourceconfig "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source-config"
	sourcepicker "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source-picker"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/wizard"

	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/circleci"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/docker"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/elasticsearch"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/filesystem"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/gcs"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/git"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/github"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/gitlab"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/huggingface"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/jenkins"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/postman"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/s3"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/syslog"
)

// Run launches the TUI and returns either the argv to hand to kingpin (when
// the user completed a scan flow) or calls os.Exit directly (when the user
// quit or completed an analyzer flow).
//
// The kingpin contract is preserved: a nil-args / empty-args return on
// user-cancel, a sliced arg vector otherwise, and analyzer.Run dispatched
// in-process when the user picked that flow.
func Run(args []string) []string {
	m := app.New()
	registerPages(m)
	m.SetInitialPage(initialPage(args))

	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v\n", err)
		os.Exit(1)
	}

	if t := m.AnalyzerType(); t != "" {
		analyzer.Run(t, m.AnalyzerInfo())
		os.Exit(0)
	}
	return m.Args()
}

// registerPages wires every page factory into the router. Factories accept
// the arbitrary Data payload that the caller PushMsg's with.
func registerPages(m *app.Model) {
	styles := m.Styles()
	keymap := m.Keymap()

	m.Register(app.PageWizard, func(data any) app.Page {
		return wizard.New(styles, keymap, data)
	})
	m.Register(app.PageSourcePicker, func(data any) app.Page {
		return sourcepicker.New(styles, keymap, data)
	})
	m.Register(app.PageSourceConfig, func(data any) app.Page {
		return sourceconfig.New(styles, keymap, data)
	})
	m.Register(app.PageAnalyzerPicker, func(data any) app.Page {
		return analyzerpicker.New(styles, keymap, data)
	})
	m.Register(app.PageAnalyzerForm, func(data any) app.Page {
		return analyzerform.New(styles, keymap, data)
	})
	m.Register(app.PageLinkCard, func(data any) app.Page {
		return linkcard.New(styles, data)
	})
}

// initialPage decides which page to open first based on the argv the parent
// main.go hands us.
//
// Preserves the previous behavior:
//   - no args               → wizard
//   - "analyze"             → analyzer-picker
//   - "analyze <known>"     → analyzer-form for that type
//   - "analyze <unknown>"   → analyzer-picker (user picks)
func initialPage(args []string) (app.PageID, any) {
	if len(args) == 0 {
		return app.PageWizard, nil
	}
	if len(args) >= 1 && args[0] == "analyze" {
		if len(args) == 1 {
			return app.PageAnalyzerPicker, nil
		}
		wanted := strings.ToLower(args[1])
		for _, a := range analyzers.AvailableAnalyzers() {
			if strings.ToLower(a) == wanted {
				return app.PageAnalyzerForm, analyzerform.Data{KeyType: wanted}
			}
		}
		return app.PageAnalyzerPicker, nil
	}
	return app.PageWizard, nil
}
