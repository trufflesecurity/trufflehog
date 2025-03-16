//go:build no_tui

package tui

import (
	"errors"
)

func Run(args []string) ([]string, error) {
	return nil, errors.New("trufflehog was compiled without this feature")
}
