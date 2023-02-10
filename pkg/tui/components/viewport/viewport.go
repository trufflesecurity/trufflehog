package viewport

import (
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/soft-serve/ui/common"
)

// Viewport represents a viewport component.
type Viewport struct {
	common common.Common
	*viewport.Model
}

// New returns a new Viewport.
func New(c common.Common) *Viewport {
	vp := viewport.New(c.Width, c.Height)
	vp.MouseWheelEnabled = true
	return &Viewport{
		common: c,
		Model:  &vp,
	}
}

// SetSize implements common.Component.
func (v *Viewport) SetSize(width, height int) {
	v.common.SetSize(width, height)
	v.Model.Width = width
	v.Model.Height = height
}

// Init implements tea.Model.
func (v *Viewport) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (v *Viewport) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	vp, cmd := v.Model.Update(msg)
	v.Model = &vp
	return v, cmd
}

// View implements tea.Model.
func (v *Viewport) View() string {
	return v.Model.View()
}

// SetContent sets the viewport's content.
func (v *Viewport) SetContent(content string) {
	v.Model.SetContent(content)
}

// GotoTop moves the viewport to the top of the log.
func (v *Viewport) GotoTop() {
	v.Model.GotoTop()
}

// GotoBottom moves the viewport to the bottom of the log.
func (v *Viewport) GotoBottom() {
	v.Model.GotoBottom()
}

// HalfViewDown moves the viewport down by half the viewport height.
func (v *Viewport) HalfViewDown() {
	v.Model.HalfViewDown()
}

// HalfViewUp moves the viewport up by half the viewport height.
func (v *Viewport) HalfViewUp() {
	v.Model.HalfViewUp()
}

// ViewUp moves the viewport up by a page.
func (v *Viewport) ViewUp() []string {
	return v.Model.ViewUp()
}

// ViewDown moves the viewport down by a page.
func (v *Viewport) ViewDown() []string {
	return v.Model.ViewDown()
}

// LineUp moves the viewport up by the given number of lines.
func (v *Viewport) LineUp(n int) []string {
	return v.Model.LineUp(n)
}

// LineDown moves the viewport down by the given number of lines.
func (v *Viewport) LineDown(n int) []string {
	return v.Model.LineDown(n)
}

// ScrollPercent returns the viewport's scroll percentage.
func (v *Viewport) ScrollPercent() float64 {
	return v.Model.ScrollPercent()
}
