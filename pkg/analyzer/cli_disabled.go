//go:build no_tui

package analyzer

import (
	"github.com/alecthomas/kingpin/v2"
)

func Command(app *kingpin.Application) *kingpin.CmdClause {
	return nil
}
