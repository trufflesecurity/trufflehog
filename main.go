package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/felixge/fgprof"
	"github.com/gorilla/mux"
	"github.com/jpillora/overseer"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/updater"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

var (
	cli            = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
	cmd            string
	debug          = cli.Flag("debug", "Run in debug mode.").Bool()
	trace          = cli.Flag("trace", "Run in trace mode.").Bool()
	jsonOut        = cli.Flag("json", "Output in JSON format.").Short('j').Bool()
	jsonLegacy     = cli.Flag("json-legacy", "Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.").Bool()
	concurrency    = cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()
	noVerification = cli.Flag("no-verification", "Don't verify the results.").Bool()
	onlyVerified   = cli.Flag("only-verified", "Only output verified results.").Bool()
	// rules = cli.Flag("rules", "Path to file with custom rules.").String()
	printAvgDetectorTime = cli.Flag("print-avg-detector-time", "Print the average time spent on each detector.").Bool()
	noUpdate             = cli.Flag("no-update", "Don't check for updates.").Bool()
	fail                 = cli.Flag("fail", "Exit with code 183 if results are found.").Bool()

	gitScan             = cli.Command("git", "Find credentials in git repositories.")
	gitScanURI          = gitScan.Arg("uri", "Git repository URL. https:// or file:// schema expected.").Required().String()
	gitScanIncludePaths = gitScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitScanExcludePaths = gitScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	gitScanSinceCommit  = gitScan.Flag("since-commit", "Commit to start scan from.").String()
	gitScanBranch       = gitScan.Flag("branch", "Branch to scan.").String()
	gitScanMaxDepth     = gitScan.Flag("max-depth", "Maximum depth of commits to scan.").Int()
	_                   = gitScan.Flag("allow", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("entropy", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("regex", "No-op flag for backwards compat.").Bool()

	githubScan           = cli.Command("github", "Find credentials in GitHub repositories.")
	githubScanEndpoint   = githubScan.Flag("endpoint", "GitHub endpoint.").Default("https://api.github.com").String()
	githubScanRepos      = githubScan.Flag("repo", `GitHub repository to scan. You can repeat this flag. Example: "https://github.com/dustin-decker/secretsandstuff"`).Strings()
	githubScanOrgs       = githubScan.Flag("org", `GitHub organization to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	githubScanToken      = githubScan.Flag("token", "GitHub token.").String()
	githubIncludeForks   = githubScan.Flag("include-forks", "Include forks in scan.").Bool()
	githubIncludeMembers = githubScan.Flag("include-members", "Include organization member repositories in scan.").Bool()

	gitlabScan = cli.Command("gitlab", "Find credentials in GitLab repositories.")
	// TODO: Add more GitLab options
	gitlabScanEndpoint = gitlabScan.Flag("endpoint", "GitLab endpoint.").Default("https://gitlab.com").String()
	gitlabScanRepos    = gitlabScan.Flag("repo", "GitLab repo url. You can repeat this flag. Leave empty to scan all repos accessible with provided credential. Example: https://gitlab.com/org/repo.git").Strings()
	gitlabScanToken    = gitlabScan.Flag("token", "GitLab token.").Required().String()

	filesystemScan        = cli.Command("filesystem", "Find credentials in a filesystem.")
	filesystemDirectories = filesystemScan.Flag("directory", "Path to directory to scan. You can repeat this flag.").Required().Strings()
	// TODO: Add more filesystem scan options. Currently only supports scanning a list of directories.
	// filesystemScanRecursive = filesystemScan.Flag("recursive", "Scan recursively.").Short('r').Bool()
	// filesystemScanIncludePaths = filesystemScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	// filesystemScanExcludePaths = filesystemScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	s3Scan         = cli.Command("s3", "Find credentials in S3 buckets.")
	s3ScanKey      = s3Scan.Flag("key", "S3 key used to authenticate.").String()
	s3ScanSecret   = s3Scan.Flag("secret", "S3 secret used to authenticate.").String()
	s3ScanCloudEnv = s3Scan.Flag("cloud-environment", "Use IAM credentials in cloud environment.").Bool()
	s3ScanBuckets  = s3Scan.Flag("bucket", "Name of S3 bucket to scan. You can repeat this flag.").Strings()

	syslogScan     = cli.Command("syslog", "Scan syslog")
	syslogAddress  = syslogScan.Flag("address", "Address and port to listen on for syslog. Example: 127.0.0.1:514").String()
	syslogProtocol = syslogScan.Flag("protocol", "Protocol to listen on. udp or tcp").String()
	syslogTLSCert  = syslogScan.Flag("cert", "Path to TLS cert.").String()
	syslogTLSKey   = syslogScan.Flag("key", "Path to TLS key.").String()
	syslogFormat   = syslogScan.Flag("format", "Log format. Can be rfc3164 or rfc5424").String()
)

func init() {
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "--") {
			split := strings.SplitN(arg, "=", 2)
			split[0] = strings.ReplaceAll(split[0], "_", "-")
			os.Args[i] = strings.Join(split, "=")
		}
	}

	cli.Version("trufflehog " + version.BuildVersion)
	cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))

	if *jsonOut {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
	switch {
	case *trace:
		logrus.SetLevel(logrus.TraceLevel)
		logrus.Debugf("running version %s", version.BuildVersion)
	case *debug:
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debugf("running version %s", version.BuildVersion)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}

func main() {
	updateCfg := overseer.Config{
		Program:       run,
		Debug:         *debug,
		RestartSignal: syscall.SIGTERM,
		// TODO: Eventually add a PreUpgrade func for signature check w/ x509 PKCS1v15
		// PreUpgrade: checkUpdateSignature(binaryPath string),
	}

	if !*noUpdate {
		updateCfg.Fetcher = updater.Fetcher(version.BuildVersion)
	}
	if version.BuildVersion == "dev" {
		updateCfg.Fetcher = nil
	}

	err := overseer.RunErr(updateCfg)
	if err != nil {
		logrus.WithError(err).Fatal("error occured with trufflehog updater 🐷")
	}
}

func run(state overseer.State) {
	if *debug {
		fmt.Println("trufflehog " + version.BuildVersion)
	}

	if *githubScanToken != "" {
		// NOTE: this kludge is here to do an authenticated shallow commit
		// TODO: refactor to better pass credentials
		os.Setenv("GITHUB_TOKEN", *githubScanToken)
	}

	// When setting a base commit, chunks must be scanned in order.
	if *gitScanSinceCommit != "" {
		*concurrency = 1
	}

	if *debug {
		go func() {
			router := mux.NewRouter()
			router.PathPrefix("/debug/pprof").Handler(http.DefaultServeMux)
			router.PathPrefix("/debug/fgprof").Handler(fgprof.Handler())
			logrus.Info("starting pprof and fgprof server on :18066 /debug/pprof and /debug/fgprof")
			if err := http.ListenAndServe(":18066", router); err != nil {
				logrus.Error(err)
			}
		}()
	}

	ctx := context.TODO()
	e := engine.Start(ctx,
		engine.WithConcurrency(*concurrency),
		engine.WithDecoders(decoders.DefaultDecoders()...),
		engine.WithDetectors(!*noVerification, engine.DefaultDetectors()...),
	)

	filter, err := common.FilterFromFiles(*gitScanIncludePaths, *gitScanExcludePaths)
	if err != nil {
		logrus.WithError(err).Fatal("could not create filter")
	}

	var repoPath string
	var remote bool
	switch cmd {
	case gitScan.FullCommand():
		repoPath, remote, err = git.PrepareRepoSinceCommit(*gitScanURI, *gitScanSinceCommit)
		if err != nil || repoPath == "" {
			logrus.WithError(err).Fatal("error preparing git repo for scanning")
		}
		if remote {
			defer os.RemoveAll(repoPath)
		}
		err = e.ScanGit(ctx, repoPath, *gitScanBranch, *gitScanSinceCommit, *gitScanMaxDepth, filter)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to scan git.")
		}
	case githubScan.FullCommand():
		if len(*githubScanOrgs) == 0 && len(*githubScanRepos) == 0 {
			log.Fatal("You must specify at least one organization or repository.")
		}
		err = e.ScanGitHub(ctx, *githubScanEndpoint, *githubScanRepos, *githubScanOrgs, *githubScanToken, *githubIncludeForks, filter, *concurrency, *githubIncludeMembers)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to scan git.")
		}
	case gitlabScan.FullCommand():
		err := e.ScanGitLab(ctx, *gitlabScanEndpoint, *gitlabScanToken, *gitlabScanRepos)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to scan GitLab.")
		}
	case filesystemScan.FullCommand():
		err := e.ScanFileSystem(ctx, *filesystemDirectories)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to scan filesystem")
		}
	case s3Scan.FullCommand():
		err := e.ScanS3(ctx, *s3ScanKey, *s3ScanSecret, *s3ScanCloudEnv, *s3ScanBuckets)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to scan S3.")
		}
	case syslogScan.FullCommand():
		err := e.ScanSyslog(ctx, *syslogAddress, *syslogProtocol, *syslogTLSCert, *syslogTLSKey, *syslogFormat, *concurrency)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to scan syslog.")
		}
	}
	// asynchronously wait for scanning to finish and cleanup
	go e.Finish()

	if !*jsonLegacy && !*jsonOut {
		fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")
	}

	// NOTE: this loop will terminate when the results channel is closed in
	// e.Finish()
	foundResults := false
	for r := range e.ResultsChan() {
		if *onlyVerified && !r.Verified {
			continue
		}
		foundResults = true

		switch {
		case *jsonLegacy:
			output.PrintLegacyJSON(&r)
		case *jsonOut:
			output.PrintJSON(&r)
		default:
			output.PrintPlainOutput(&r)
		}
	}
	logrus.Debugf("scanned %d chunks", e.ChunksScanned())

	if *printAvgDetectorTime {
		printAverageDetectorTime(e)
	}

	if foundResults && *fail {
		logrus.Debug("exiting with code 183 because results were found")
		os.Exit(183)
	}
}

func printAverageDetectorTime(e *engine.Engine) {
	fmt.Fprintln(os.Stderr, "Average detector time is the measurement of average time spent on each detector when results are returned.")
	for detectorName, durations := range e.DetectorAvgTime() {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(len(durations))
		fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, avgDuration)
	}
}
