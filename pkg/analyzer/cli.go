package analyzer

import (
	"fmt"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airbrake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/asana"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/bitbucket"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/gitlab"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/huggingface"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailchimp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailgun"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mysql"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/openai"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/opsgenie"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postgres"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postman"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/shopify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/slack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sourcegraph"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/square"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/stripe"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/twilio"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/tui"
)

var (
	// TODO: Add list of supported key types.
	analyzeKeyType *string
)

func Command(app *kingpin.Application) *kingpin.CmdClause {
	cli := app.Command("analyze", "Analyze API keys for fine-grained permissions information.")

	keyTypeHelp := fmt.Sprintf(
		"Type of key to analyze. Omit to interactively choose. Available key types: %s",
		strings.Join(analyzers.AvailableAnalyzers(), ", "),
	)
	// Lowercase the available analyzers.
	availableAnalyzers := make([]string, len(analyzers.AvailableAnalyzers()))
	for i, a := range analyzers.AvailableAnalyzers() {
		availableAnalyzers[i] = strings.ToLower(a)
	}
	analyzeKeyType = cli.Arg("key-type", keyTypeHelp).Enum(availableAnalyzers...)

	return cli
}

func Run(cmd string) {
	keyType, secretInfo, err := tui.Run(*analyzeKeyType)
	if err != nil {
		// TODO: Log error.
		return
	}
	if secretInfo.Cfg == nil {
		secretInfo.Cfg = &config.Config{}
	}
	switch strings.ToLower(keyType) {
	case "github":
		github.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "sendgrid":
		sendgrid.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "openai":
		openai.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "postgres":
		postgres.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "mysql":
		mysql.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "slack":
		slack.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "twilio":
		twilio.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["sid"], secretInfo.Parts["key"])
	case "airbrake":
		airbrake.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "huggingface":
		huggingface.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "stripe":
		stripe.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "gitlab":
		gitlab.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "mailchimp":
		mailchimp.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "postman":
		postman.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "bitbucket":
		bitbucket.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "asana":
		asana.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "mailgun":
		mailgun.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "square":
		square.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "sourcegraph":
		sourcegraph.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "shopify":
		shopify.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"], secretInfo.Parts["url"])
	case "opsgenie":
		opsgenie.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	}
}
