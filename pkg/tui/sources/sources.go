package sources

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/circleci"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/docker"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/filesystem"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/gcs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/gitlab"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/s3"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources/syslog"
)

func GetSourceNotes(sourceName string) string {
	source := strings.ToLower(sourceName)
	switch source {
	case "github":
		return github.GetNote()

	default:
		return ""
	}
}

type CmdModel interface {
	tea.Model
	Cmd() string
	Summary() string
}

func GetSourceFields(sourceName string) CmdModel {
	source := strings.ToLower(sourceName)

	switch source {
	case "git":
		return git.GetFields()
	case "github":
		return github.GetFields()
	case "gitlab":
		return gitlab.GetFields()
	case "filesystem":
		return filesystem.GetFields()
	case "aws s3":
		return s3.GetFields()
	case "gcs (google cloud storage)":
		return gcs.GetFields()
	case "syslog":
		return syslog.GetFields()
	case "circleci":
		return circleci.GetFields()
	case "docker":
		return docker.GetFields()
	}

	return nil
}
