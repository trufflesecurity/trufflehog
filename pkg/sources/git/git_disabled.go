//go:build no_git

package git

import (
	"errors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func PrepareRepo(ctx context.Context, uriString string) (string, bool, error) {
	return "", false, errors.New("trufflehog was compiled without the Git source")
}
