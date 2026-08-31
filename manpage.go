package main

import (
	"os"

	"github.com/alecthomas/kingpin/v2"
)

const enhancedManPageTemplate = `{{define "FormatFlags" -}}
{{range .Flags -}}
{{if not .Hidden -}}
.TP
\fB{{if .Short}}-{{.Short|Char}}, {{end}}--{{.Name}}{{if not .IsBoolFlag}}={{.FormatPlaceHolder}}{{end -}}\fR
{{.Help}}
{{end -}}
{{end -}}
{{end -}}

{{define "FormatCommand" -}}
{{if .FlagSummary}} {{.FlagSummary}}{{end -}}
{{range .Args}}{{if not .Hidden}} {{if not .Required}}[{{end}}{{if .PlaceHolder}}{{.PlaceHolder}}{{else}}<{{.Name}}>{{end}}{{if .Value|IsCumulative}}...{{end}}{{if not .Required}}]{{end}}{{end}}{{end -}}
{{end -}}

{{define "FormatCommands" -}}
{{range .FlattenedCommands -}}
{{if not .Hidden -}}
.SS
\fB{{.FullCommand}}{{template "FormatCommand" . -}}\fR
{{.Help}}
{{template "FormatFlags" . -}}
{{end -}}
{{end -}}
{{end -}}

{{define "FormatUsage" -}}
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end -}}\fR
{{end -}}

.TH TRUFFLEHOG 1 "" "{{.App.Version}}" "Truffle Security"
.SH NAME
trufflehog \- find credentials in various sources
.SH SYNOPSIS
.TP
\fBtrufflehog{{template "FormatUsage" .App}}
.SH DESCRIPTION
{{.App.Help}}
.PP
TruffleHog scans various data sources for verified and
unverified secrets such as API keys, passwords, and other
credentials. It supports scanning git repositories, GitHub
and GitLab organizations, filesystems, S3 buckets, GCS
buckets, Docker images, CI/CD systems, and more.
.PP
When run without a command in an interactive terminal,
\fBtrufflehog\fR launches a TUI (text user interface) that
guides you through selecting a scan source and configuring
options.
.SH OPTIONS
{{template "FormatFlags" .App -}}
{{if .App.Commands -}}
.SH COMMANDS
{{template "FormatCommands" .App -}}
{{end -}}
.SH "EXIT STATUS"
.TP
.B 0
Successful execution.
.TP
.B 183
Credentials were found and \fB\-\-fail\fR was specified.
.TP
.B 1
An error occurred during scanning.
.SH EXAMPLES
.TP
.B Launch the interactive TUI
.EX
trufflehog
.EE
.TP
.B Scan a git repository
.EX
trufflehog git https://github.com/example/repo.git
.EE
.TP
.B Scan a GitHub organization
.EX
trufflehog github \-\-org=trufflesecurity \-\-token=$GITHUB_TOKEN
.EE
.TP
.B Scan a local filesystem
.EX
trufflehog filesystem /path/to/directory
.EE
.TP
.B Scan an S3 bucket
.EX
trufflehog s3 \-\-bucket=my\-bucket \-\-cloud\-environment
.EE
.TP
.B Scan a Docker image
.EX
trufflehog docker \-\-image=myregistry/myimage:latest
.EE
.TP
.B Read from stdin
.EX
cat secrets.txt | trufflehog stdin
.EE
.TP
.B Output JSON and filter with jq
.EX
trufflehog git https://github.com/example/repo.git \-\-json \e
  | jq 'select(.Verified == true)'
.EE
.TP
.B Fail in CI if secrets are found
.EX
trufflehog git file://. \-\-fail \-\-results=verified,unknown
.EE
.TP
.B Use a configuration file
.EX
trufflehog git https://github.com/example/repo.git \e
  \-\-config=trufflehog\-config.yaml
.EE
.SH ENVIRONMENT
.TP
.B GITHUB_TOKEN
Authentication token for GitHub scanning.
.TP
.B GITLAB_TOKEN
Authentication token for GitLab scanning.
.TP
.B AWS_ACCESS_KEY_ID
AWS access key for S3 scanning.
.TP
.B AWS_SECRET_ACCESS_KEY
AWS secret key for S3 scanning.
.TP
.B AWS_SESSION_TOKEN
AWS session token for temporary credentials.
.TP
.B GOOGLE_CLOUD_PROJECT
GCP project ID for GCS scanning.
.TP
.B GOOGLE_API_KEY
GCP API key for GCS scanning.
.TP
.B CIRCLECI_TOKEN
Authentication token for CircleCI scanning.
.TP
.B DOCKER_TOKEN
Authentication token for Docker scanning.
.TP
.B TRAVISCI_TOKEN
Authentication token for TravisCI scanning.
.TP
.B POSTMAN_TOKEN
Authentication token for Postman scanning.
.TP
.B HUGGINGFACE_TOKEN
Authentication token for HuggingFace scanning.
.TP
.B ELASTICSEARCH_NODES
Comma-separated list of Elasticsearch nodes.
.TP
.B JENKINS_URL
URL of the Jenkins server.
.SH FILES
.TP
.I trufflehog\-config.yaml
Optional configuration file specified via \fB\-\-config\fR.
See the project documentation for the configuration
file format.
.SH BUGS
Report bugs at
.UR https://github.com/trufflesecurity/trufflehog/issues
the TruffleHog issue tracker
.UE .
.SH "SEE ALSO"
.UR https://github.com/trufflesecurity/trufflehog
TruffleHog on GitHub
.UE ,
.UR https://trufflesecurity.com
Truffle Security website
.UE .
`

func registerManPageFlag(app *kingpin.Application) {
	app.Flag("generate-man-page", "Generate man page.").
		Hidden().
		PreAction(func(c *kingpin.ParseContext) error {
			app.Writer(os.Stdout)
			if err := app.UsageForContextWithTemplate(c, 2, enhancedManPageTemplate); err != nil {
				return err
			}
			os.Exit(0)
			return nil
		}).Bool()
}
