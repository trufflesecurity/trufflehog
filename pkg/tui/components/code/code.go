package code

import (
	"fmt"
	"strings"
	"sync"

	"github.com/alecthomas/chroma/lexers"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	gansi "github.com/charmbracelet/glamour/ansi"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/soft-serve/ui/common"
	vp "github.com/charmbracelet/soft-serve/ui/components/viewport"
	"github.com/muesli/termenv"
)

const (
	tabWidth = 4
)

var (
	lineDigitStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("239"))
	lineBarStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("236"))
)

// Code is a code snippet.
type Code struct {
	*vp.Viewport
	common         common.Common
	content        string
	extension      string
	renderContext  gansi.RenderContext
	renderMutex    sync.Mutex
	styleConfig    gansi.StyleConfig
	showLineNumber bool

	NoContentStyle lipgloss.Style
	LineDigitStyle lipgloss.Style
	LineBarStyle   lipgloss.Style
}

// New returns a new Code.
func New(c common.Common, content, extension string) *Code {
	r := &Code{
		common:         c,
		content:        content,
		extension:      extension,
		Viewport:       vp.New(c),
		NoContentStyle: c.Styles.CodeNoContent.Copy(),
		LineDigitStyle: lineDigitStyle,
		LineBarStyle:   lineBarStyle,
	}
	st := common.StyleConfig()
	r.styleConfig = st
	r.renderContext = gansi.NewRenderContext(gansi.Options{
		ColorProfile: termenv.TrueColor,
		Styles:       st,
	})
	r.SetSize(c.Width, c.Height)
	return r
}

// SetShowLineNumber sets whether to show line numbers.
func (r *Code) SetShowLineNumber(show bool) {
	r.showLineNumber = show
}

// SetSize implements common.Component.
func (r *Code) SetSize(width, height int) {
	r.common.SetSize(width, height)
	r.Viewport.SetSize(width, height)
}

// SetContent sets the content of the Code.
func (r *Code) SetContent(c, ext string) tea.Cmd {
	r.content = c
	r.extension = ext
	return r.Init()
}

// Init implements tea.Model.
func (r *Code) Init() tea.Cmd {
	w := r.common.Width
	c := r.content
	if c == "" {
		r.Viewport.Model.SetContent(r.NoContentStyle.String())
		return nil
	}
	f, err := r.renderFile(r.extension, c, w)
	if err != nil {
		return common.ErrorCmd(err)
	}
	r.Viewport.Model.SetContent(f)
	return nil
}

// Update implements tea.Model.
func (r *Code) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0)
	switch msg.(type) {
	case tea.WindowSizeMsg:
		// Recalculate content width and line wrap.
		cmds = append(cmds, r.Init())
	}
	v, cmd := r.Viewport.Update(msg)
	r.Viewport = v.(*vp.Viewport)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}
	return r, tea.Batch(cmds...)
}

// View implements tea.View.
func (r *Code) View() string {
	return r.Viewport.View()
}

// GotoTop moves the viewport to the top of the log.
func (r *Code) GotoTop() {
	r.Viewport.GotoTop()
}

// GotoBottom moves the viewport to the bottom of the log.
func (r *Code) GotoBottom() {
	r.Viewport.GotoBottom()
}

// HalfViewDown moves the viewport down by half the viewport height.
func (r *Code) HalfViewDown() {
	r.Viewport.HalfViewDown()
}

// HalfViewUp moves the viewport up by half the viewport height.
func (r *Code) HalfViewUp() {
	r.Viewport.HalfViewUp()
}

// ViewUp moves the viewport up by a page.
func (r *Code) ViewUp() []string {
	return r.Viewport.ViewUp()
}

// ViewDown moves the viewport down by a page.
func (r *Code) ViewDown() []string {
	return r.Viewport.ViewDown()
}

// LineUp moves the viewport up by the given number of lines.
func (r *Code) LineUp(n int) []string {
	return r.Viewport.LineUp(n)
}

// LineDown moves the viewport down by the given number of lines.
func (r *Code) LineDown(n int) []string {
	return r.Viewport.LineDown(n)
}

// ScrollPercent returns the viewport's scroll percentage.
func (r *Code) ScrollPercent() float64 {
	return r.Viewport.ScrollPercent()
}

func (r *Code) glamourize(w int, md string) (string, error) {
	r.renderMutex.Lock()
	defer r.renderMutex.Unlock()
	if w > 120 {
		w = 120
	}
	tr, err := glamour.NewTermRenderer(
		glamour.WithStyles(r.styleConfig),
		glamour.WithWordWrap(w),
	)

	if err != nil {
		return "", err
	}
	mdt, err := tr.Render(md)
	if err != nil {
		return "", err
	}
	return mdt, nil
}

func (r *Code) renderFile(path, content string, width int) (string, error) {
	// FIXME chroma & glamour might break wrapping when using tabs since tab
	// width depends on the terminal. This is a workaround to replace tabs with
	// 4-spaces.
	content = strings.ReplaceAll(content, "\t", strings.Repeat(" ", tabWidth))
	lexer := lexers.Fallback
	if path == "" {
		lexer = lexers.Analyse(content)
	} else {
		lexer = lexers.Match(path)
	}
	lang := ""
	if lexer != nil && lexer.Config() != nil {
		lang = lexer.Config().Name
	}
	var c string
	if lang == "markdown" {
		md, err := r.glamourize(width, content)
		if err != nil {
			return "", err
		}
		c = md
	} else {
		formatter := &gansi.CodeBlockElement{
			Code:     content,
			Language: lang,
		}
		s := strings.Builder{}
		rc := r.renderContext
		if r.showLineNumber {
			st := common.StyleConfig()
			var m uint
			st.CodeBlock.Margin = &m
			rc = gansi.NewRenderContext(gansi.Options{
				ColorProfile: termenv.TrueColor,
				Styles:       st,
			})
		}
		err := formatter.Render(&s, rc)
		if err != nil {
			return "", err
		}
		c = s.String()
		if r.showLineNumber {
			var ml int
			c, ml = withLineNumber(c)
			width -= ml
		}
	}
	// Fix styling when after line breaks.
	// https://github.com/muesli/reflow/issues/43
	//
	// TODO: solve this upstream in Glamour/Reflow.
	return lipgloss.NewStyle().Width(width).Render(c), nil
}

func withLineNumber(s string) (string, int) {
	lines := strings.Split(s, "\n")
	// NB: len() is not a particularly safe way to count string width (because
	// it's counting bytes instead of runes) but in this case it's okay
	// because we're only dealing with digits, which are one byte each.
	mll := len(fmt.Sprintf("%d", len(lines)))
	for i, l := range lines {
		digit := fmt.Sprintf("%*d", mll, i+1)
		bar := "│"
		digit = lineDigitStyle.Render(digit)
		bar = lineBarStyle.Render(bar)
		if i < len(lines)-1 || len(l) != 0 {
			// If the final line was a newline we'll get an empty string for
			// the final line, so drop the newline altogether.
			lines[i] = fmt.Sprintf(" %s %s %s", digit, bar, l)
		}
	}
	return strings.Join(lines, "\n"), mll
}
