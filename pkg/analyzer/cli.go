package analyzer

import (
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
)

var (
	// TODO: Add list of supported key types.
	list    *kingpin.CmdClause
	showAll *bool
	log     *bool

	githubScan *kingpin.CmdClause
	githubKey  *string

	sendgridScan *kingpin.CmdClause
	sendgridKey  *string

	openAIScan *kingpin.CmdClause
	openaiKey  *string

	postgresScan          *kingpin.CmdClause
	postgresConnectionStr *string

	mysqlScan          *kingpin.CmdClause
	mysqlConnectionStr *string

	// mongodbScan          *kingpin.CmdClause
	// mongodbConnectionStr *string

	slackScan *kingpin.CmdClause
	slackKey  *string

	twilioScan *kingpin.CmdClause
	twilioKey  *string

	airbrakeScan *kingpin.CmdClause
	airbrakeKey  *string

	huggingfaceScan *kingpin.CmdClause
	huggingfaceKey  *string

	stripeScan *kingpin.CmdClause
	stripeKey  *string

	gitlabScan *kingpin.CmdClause
	gitlabKey  *string

	mailchimpScan *kingpin.CmdClause
	mailchimpKey  *string

	// mandrillScan *kingpin.CmdClause
	// mandrillKey  *string

	postmanScan *kingpin.CmdClause
	postmanKey  *string

	bitbucketScan *kingpin.CmdClause
	bitbucketKey  *string

	asanaScan *kingpin.CmdClause
	asanaKey  *string

	mailgunScan *kingpin.CmdClause
	mailgunKey  *string

	squareScan *kingpin.CmdClause
	squareKey  *string

	sourcegraphScan *kingpin.CmdClause
	sourcegraphKey  *string

	shopifyScan     *kingpin.CmdClause
	shopifyKey      *string
	shopifyStoreURL *string

	opsgenieScan *kingpin.CmdClause
	opsgenieKey  *string
)

func Command(app *kingpin.Application) *kingpin.CmdClause {
	// TODO: Add list of supported key types.
	cli := app.Command("analyze", "Analyze API keys for fine-grained permissions information").Hidden()
	list = cli.Command("list", "List supported API providers")
	showAll = cli.Flag("show-all", "Show all data, including permissions not available to this account + publicly-available data related to this account.").Default("false").Bool()
	log = cli.Flag("log", "Log all HTTP requests sent during analysis to a file").Default("false").Bool()

	githubScan = cli.Command("github", "Scan a GitHub API key")
	githubKey = githubScan.Arg("key", "GitHub Key.").Required().String()

	sendgridScan = cli.Command("sendgrid", "Scan a Sendgrid API key")
	sendgridKey = sendgridScan.Arg("key", "Sendgrid Key.").Required().String()

	openAIScan = cli.Command("openai", "Scan an OpenAI API key")
	openaiKey = openAIScan.Arg("key", "OpenAI Key.").Required().String()

	postgresScan = cli.Command("postgres", "Scan a Postgres connection string")
	postgresConnectionStr = postgresScan.Arg("connection-string", "Postgres Connection String. As a reference, here's an example: postgresql://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]").Required().String()

	mysqlScan = cli.Command("mysql", "Scan a MySQL connection string")
	mysqlConnectionStr = mysqlScan.Arg("connection-string", "MySQL Connection String. As a reference, here's an example: mysql://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]").Required().String()

	// mongodbScan          = cli.Command("mongodb", "Scan a MongoDB connection string")
	// mongodbConnectionStr = mongodbScan.Arg("connection-string", "MongoDB Connection String. As a reference, here's an example: mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[defaultauthdb][?options]]").Required().String()

	slackScan = cli.Command("slack", "Scan a Slack API key")
	slackKey = slackScan.Arg("key", "Slack Key.").Required().String()

	twilioScan = cli.Command("twilio", "Scan a Twilio API key")
	twilioKey = twilioScan.Arg("key", "Twilio API Key SID & Secret (ex: keySID:keySecret).").Required().String()

	airbrakeScan = cli.Command("airbrake", "Scan an Airbrake User Key or Token")
	airbrakeKey = airbrakeScan.Arg("key", "Airbrake User Key or Token.").Required().String()

	huggingfaceScan = cli.Command("huggingface", "Scan a Huggingface API key")
	huggingfaceKey = huggingfaceScan.Arg("key", "Huggingface Key.").Required().String()

	stripeScan = cli.Command("stripe", "Scan a Stripe API key")
	stripeKey = stripeScan.Arg("key", "Stripe Key.").Required().String()

	gitlabScan = cli.Command("gitlab", "Scan a GitLab API key")
	gitlabKey = gitlabScan.Arg("key", "GitLab Key.").Required().String()

	mailchimpScan = cli.Command("mailchimp", "Scan a Mailchimp API key")
	mailchimpKey = mailchimpScan.Arg("key", "Mailchimp Key.").Required().String()

	// mandrillScan = cli.Command("mandrill", "Scan a Mandrill API key")
	// mandrillKey  = mandrillScan.Arg("key", "Mandril Key.").Required().String()

	postmanScan = cli.Command("postman", "Scan a Postman API key")
	postmanKey = postmanScan.Arg("key", "Postman Key.").Required().String()

	bitbucketScan = cli.Command("bitbucket", "Scan a Bitbucket Access Token")
	bitbucketKey = bitbucketScan.Arg("key", "Bitbucket Access Token.").Required().String()

	asanaScan = cli.Command("asana", "Scan an Asana API key")
	asanaKey = asanaScan.Arg("key", "Asana Key.").Required().String()

	mailgunScan = cli.Command("mailgun", "Scan a Mailgun API key")
	mailgunKey = mailgunScan.Arg("key", "Mailgun Key.").Required().String()

	squareScan = cli.Command("square", "Scan a Square API key")
	squareKey = squareScan.Arg("key", "Square Key.").Required().String()

	sourcegraphScan = cli.Command("sourcegraph", "Scan a Sourcegraph Access Token")
	sourcegraphKey = sourcegraphScan.Arg("key", "Sourcegraph Access Token.").Required().String()

	shopifyScan = cli.Command("shopify", "Scan a Shopify API key")
	shopifyKey = shopifyScan.Arg("key", "Shopify Key.").Required().String()
	shopifyStoreURL = shopifyScan.Arg("store-url", "Shopify Store Domain (ex: 22297c-c6.myshopify.com).").Required().String()

	opsgenieScan = cli.Command("opsgenie", "Scan an Opsgenie API key")
	opsgenieKey = opsgenieScan.Arg("key", "Opsgenie Key.").Required().String()

	return cli
}

func Run(cmd string) {
	// Initialize configuration
	cfg := &config.Config{
		LoggingEnabled: *log,
		ShowAll:        *showAll,
	}
	switch cmd {
	case list.FullCommand():
		panic("todo")
	case githubScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("github")
		github.AnalyzeAndPrintPermissions(cfg, *githubKey)
	case sendgridScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("sendgrid")
		sendgrid.AnalyzePermissions(cfg, *sendgridKey)
	case openAIScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("openai")
		openai.AnalyzeAndPrintPermissions(cfg, *openaiKey)
	case postgresScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("postgres")
		postgres.AnalyzePermissions(cfg, *postgresConnectionStr)
	case mysqlScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("mysql")
		mysql.AnalyzePermissions(cfg, *mysqlConnectionStr)
	case slackScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("slack")
		slack.AnalyzePermissions(cfg, *slackKey)
	case twilioScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("twilio")
		twilio.AnalyzePermissions(cfg, *twilioKey)
	case airbrakeScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("airbrake")
		airbrake.AnalyzePermissions(cfg, *airbrakeKey)
	case huggingfaceScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("huggingface")
		huggingface.AnalyzePermissions(cfg, *huggingfaceKey)
	case stripeScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("stripe")
		stripe.AnalyzePermissions(cfg, *stripeKey)
	case gitlabScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("gitlab")
		gitlab.AnalyzePermissions(cfg, *gitlabKey)
	case mailchimpScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("mailchimp")
		mailchimp.AnalyzePermissions(cfg, *mailchimpKey)
	case postmanScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("postman")
		postman.AnalyzePermissions(cfg, *postmanKey)
	case bitbucketScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("bitbucket")
		bitbucket.AnalyzePermissions(cfg, *bitbucketKey)
	case asanaScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("asana")
		asana.AnalyzePermissions(cfg, *asanaKey)
	case mailgunScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("mailgun")
		mailgun.AnalyzePermissions(cfg, *mailgunKey)
	case squareScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("square")
		square.AnalyzePermissions(cfg, *squareKey)
	case sourcegraphScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("sourcegraph")
		sourcegraph.AnalyzePermissions(cfg, *sourcegraphKey)
	case shopifyScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("shopify")
		shopify.AnalyzePermissions(cfg, *shopifyKey, *shopifyStoreURL)
	case opsgenieScan.FullCommand():
		cfg.LogFile = analyzers.CreateLogFileName("opsgenie")
		opsgenie.AnalyzePermissions(cfg, *opsgenieKey)
	}
}
