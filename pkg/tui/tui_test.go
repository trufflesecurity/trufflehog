package tui

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	analyzerform "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/analyzer-form"
)

func TestInitialPage(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantID  app.PageID
		wantKey string // analyzer-form KeyType when data is analyzerform.Data
	}{
		{name: "no args → wizard", args: nil, wantID: app.PageWizard},
		{name: "empty args → wizard", args: []string{}, wantID: app.PageWizard},
		{name: "analyze only → picker", args: []string{"analyze"}, wantID: app.PageAnalyzerPicker},
		{name: "analyze unknown → picker", args: []string{"analyze", "bogus-analyzer"}, wantID: app.PageAnalyzerPicker},
		{name: "analyze github → form", args: []string{"analyze", "github"}, wantID: app.PageAnalyzerForm, wantKey: "github"},
		{name: "analyze GitHub casefold → form", args: []string{"analyze", "GitHub"}, wantID: app.PageAnalyzerForm, wantKey: "github"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			id, data := initialPage(tc.args)
			if id != tc.wantID {
				t.Fatalf("id: got %q, want %q", id, tc.wantID)
			}
			if tc.wantKey == "" {
				return
			}
			d, ok := data.(analyzerform.Data)
			if !ok {
				t.Fatalf("data: got %T, want analyzerform.Data", data)
			}
			if d.KeyType != tc.wantKey {
				t.Errorf("KeyType: got %q, want %q", d.KeyType, tc.wantKey)
			}
		})
	}
}
