package analyzer

import (
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airbrake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airtable/airtableoauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airtable/airtablepat"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/anthropic"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/asana"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/bitbucket"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/databricks"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/datadog"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/digitalocean"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/dockerhub"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/dropbox"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/elevenlabs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/fastly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/figma"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/gitlab"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/groq"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/huggingface"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/jira"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/launchdarkly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailchimp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailgun"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/monday"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mux"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mysql"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/netlify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/ngrok"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/notion"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/openai"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/opsgenie"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/plaid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/planetscale"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postgres"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/posthog"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postman"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/privatekey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/shopify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/slack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sourcegraph"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/square"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/stripe"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/twilio"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type SecretInfo struct {
	Parts map[string]string
	Cfg   *config.Config
}

func Command(app *kingpin.Application) *kingpin.CmdClause {
	return app.Command("analyze", "Analyze API keys for fine-grained permissions information.")
}

func Run(keyType string, secretInfo SecretInfo) {
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
	case "privatekey":
		privatekey.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "notion":
		notion.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "dockerhub":
		dockerhub.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["username"], secretInfo.Parts["pat"])
	case "anthropic":
		anthropic.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "digitalocean":
		digitalocean.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "elevenlabs":
		elevenlabs.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "planetscale":
		planetscale.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["id"], secretInfo.Parts["token"])
	case "airtableoauth":
		airtableoauth.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "airtablepat":
		airtablepat.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "groq":
		groq.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "launchdarkly":
		launchdarkly.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "figma":
		figma.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "plaid":
		plaid.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["secret"], secretInfo.Parts["id"], secretInfo.Parts["token"])
	case "netlify":
		netlify.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "fastly":
		fastly.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "monday":
		monday.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "datadog":
		datadog.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["apiKey"], secretInfo.Parts["appKey"])
	case "ngrok":
		ngrok.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "mux":
		mux.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"], secretInfo.Parts["secret"])
	case "posthog":
		posthog.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "dropbox":
		dropbox.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["key"])
	case "databricks":
		databricks.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["domain"], secretInfo.Parts["token"])
	case "jira":
		jira.AnalyzeAndPrintPermissions(secretInfo.Cfg, secretInfo.Parts["domain"], secretInfo.Parts["email"], secretInfo.Parts["token"])
	}
}
