package tui

import (
	"os"
)

func Run() []string {
	startModel{}.Run()
	os.Exit(0)
	return nil
}
