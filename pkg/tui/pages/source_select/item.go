package source_select

import (
	"gopkg.in/alecthomas/kingpin.v2"
)

type SourceItem struct {
	title       string
	description string
	cmd         *kingpin.CmdModel
}

func (i SourceItem) isEnterprise() bool {
	return i.cmd == nil
}

func (i SourceItem) ID() string { return i.title }

func (i SourceItem) Title() string {
	if i.isEnterprise() {
		return "💸 " + i.title
	}
	return i.title
}
func (i SourceItem) Description() string {
	if i.isEnterprise() {
		return i.description + " (Enterprise only)"
	}
	return i.description
}

func (i SourceItem) FilterValue() string { return i.title + i.description }
