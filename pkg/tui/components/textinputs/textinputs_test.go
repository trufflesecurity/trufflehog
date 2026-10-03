package textinputs

import (
	"strings"
	"testing"
)

func TestSkipButtonViewIsRenderedLazily(t *testing.T) {
	m := New(nil).SetSkip(true)

	view := m.View()

	if !strings.Contains(view, "Run with defaults") {
		t.Fatalf("expected skip button text in view, got %q", view)
	}
}

func TestSkipButtonViewIsHiddenByDefault(t *testing.T) {
	m := New(nil)

	view := m.View()

	if strings.Contains(view, "Run with defaults") {
		t.Fatalf("did not expect skip button text in default view, got %q", view)
	}
}
