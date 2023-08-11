package common

import (
	"github.com/aymanbagabas/go-osc52"
	zone "github.com/lrstanley/bubblezone"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/keymap"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

// Common is a struct all components should embed.
type Common struct {
	Copy   *osc52.Output
	Styles *styles.Styles
	KeyMap *keymap.KeyMap
	Width  int
	Height int
	Zone   *zone.Manager
}

// SetSize sets the width and height of the common struct.
func (c *Common) SetSize(width, height int) {
	c.Width = width
	c.Height = height
}
