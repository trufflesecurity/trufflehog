package common

import (
	"github.com/charmbracelet/glamour"
	gansi "github.com/charmbracelet/glamour/ansi"
)

func strptr(s string) *string {
	return &s
}

// StyleConfig returns the default Glamour style configuration.
func StyleConfig() gansi.StyleConfig {
	noColor := strptr("")
	s := glamour.DarkStyleConfig
	s.H1.BackgroundColor = noColor
	s.H1.Prefix = "# "
	s.H1.Suffix = ""
	s.H1.Color = strptr("39")
	s.Document.StylePrimitive.Color = noColor
	s.CodeBlock.Chroma.Text.Color = noColor
	s.CodeBlock.Chroma.Name.Color = noColor
	// This fixes an issue with the default style config. For example
	// highlighting empty spaces with red in Dockerfile type.
	s.CodeBlock.Chroma.Error.BackgroundColor = noColor
	return s
}
