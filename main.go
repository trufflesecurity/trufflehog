package main

import (
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/felixge/fgprof"
	"github.com/go-logr/logr"
	"github.com/jpillora/overseer"
	"github.com/mattn/go-isatty"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui"
	"github.com/trufflesecurity/trufflehog/v3/pkg/updater"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

var (
	cli                 = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
	cmd                 string
	debug               = cli.Flag("debug", "Run in debug mode.").Bool()
	trace               = cli.Flag("trace", "Run in trace mode.").Bool()
	profile             = cli.Flag("profile", "Enables profiling and sets a pprof and fgprof server on :18066.").Bool()
	localDev            = cli.Flag("local-dev", "Hidden feature to disable overseer for local dev.").Hidden().Bool()
	jsonOut             = cli.Flag("json", "Output in JSON format.").Short('j').Bool()
	jsonLegacy          = cli.Flag("json-legacy", "Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.").Bool()
	gitHubActionsFormat = cli.Flag("github-actions", "Output in GitHub Actions format.").Bool()
	concurrency         = cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()
	noVerification      = cli.Flag("no-verification", "Don't verify the results.").Bool()
	onlyVerified        = cli.Flag("only-verified", "Only output verified results.").Bool()
	results             = cli.Flag("results", "Specifies which type(s) of results to output: verified, unknown, unverified. Defaults to all types.").Hidden().String()

	allowVerificationOverlap = cli.Flag("allow-verification-overlap", "Allow verification of similar credentials across detectors").Bool()
	filterUnverified         = cli.Flag("filter-unverified", "Only output first unverified result per chunk per detector if there are more than one results.").Bool()
	filterEntropy            = cli.Flag("filter-entropy", "Filter unverified results with Shannon entropy. Start with 3.0.").Float64()
	configFilename           = cli.Flag("config", "Path to configuration file.").ExistingFile()
	// rules = cli.Flag("rules", "Path to file with custom rules.").String()
	printAvgDetectorTime = cli.Flag("print-avg-detector-time", "Print the average time spent on each detector.").Bool()
	noUpdate             = cli.Flag("no-update", "Don't check for updates.").Bool()
	fail                 = cli.Flag("fail", "Exit with code 183 if results are found.").Bool()
	verifiers            = cli.Flag("verifier", "Set custom verification endpoints.").StringMap()
	customVerifiersOnly  = cli.Flag("custom-verifiers-only", "Only use custom verification endpoints.").Bool()
	archiveMaxSize       = cli.Flag("archive-max-size", "Maximum size of archive to scan. (Byte units eg. 512B, 2KB, 4MB)").Bytes()
	archiveMaxDepth      = cli.Flag("archive-max-depth", "Maximum depth of archive to scan.").Int()
	archiveTimeout       = cli.Flag("archive-timeout", "Maximum time to spend extracting an archive.").Duration()
	includeDetectors     = cli.Flag("include-detectors", "Comma separated list of detector types to include. Protobuf name or IDs may be used, as well as ranges.").Default("all").String()
	excludeDetectors     = cli.Flag("exclude-detectors", "Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.").String()
	jobReportFile        = cli.Flag("output-report", "Write a scan report to the provided path.").Hidden().OpenFile(os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)

	gitScan             = cli.Command("git", "Find credentials in git repositories.")
	gitScanURI          = gitScan.Arg("uri", "Git repository URL. https://, file://, or ssh:// schema expected.").Required().String()
	gitScanIncludePaths = gitScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitScanExcludePaths = gitScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	gitScanExcludeGlobs = gitScan.Flag("exclude-globs", "Comma separated list of globs to exclude in scan. This option filters at the `git log` level, resulting in faster scans.").String()
	gitScanSinceCommit  = gitScan.Flag("since-commit", "Commit to start scan from.").String()
	gitScanBranch       = gitScan.Flag("branch", "Branch to scan.").String()
	gitScanMaxDepth     = gitScan.Flag("max-depth", "Maximum depth of commits to scan.").Int()
	gitScanBare         = gitScan.Flag("bare", "Scan bare repository (e.g. useful while using in pre-receive hooks)").Bool()
	_                   = gitScan.Flag("allow", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("entropy", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("regex", "No-op flag for backwards compat.").Bool()

	githubScan           = cli.Command("github", "Find credentials in GitHub repositories.")
	githubScanEndpoint   = githubScan.Flag("endpoint", "GitHub endpoint.").Default("https://api.github.com").String()
	githubScanRepos      = githubScan.Flag("repo", `GitHub repository to scan. You can repeat this flag. Example: "https://github.com/dustin-decker/secretsandstuff"`).Strings()
	githubScanOrgs       = githubScan.Flag("org", `GitHub organization to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	githubScanToken      = githubScan.Flag("token", "GitHub token. Can be provided with environment variable GITHUB_TOKEN.").Envar("GITHUB_TOKEN").String()
	githubIncludeForks   = githubScan.Flag("include-forks", "Include forks in scan.").Bool()
	githubIncludeMembers = githubScan.Flag("include-members", "Include organization member repositories in scan.").Bool()
	githubIncludeRepos   = githubScan.Flag("include-repos", `Repositories to include in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/trufflehog", "trufflesecurity/t*"`).Strings()
	githubIncludeWikis   = githubScan.Flag("include-wikis", "Include repository wikisin scan.").Bool()

	githubExcludeRepos      = githubScan.Flag("exclude-repos", `Repositories to exclude in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/driftwood", "trufflesecurity/d*"`).Strings()
	githubScanIncludePaths  = githubScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	githubScanExcludePaths  = githubScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	githubScanIssueComments = githubScan.Flag("issue-comments", "Include issue descriptions and comments in scan.").Bool()
	githubScanPRComments    = githubScan.Flag("pr-comments", "Include pull request descriptions and comments in scan.").Bool()
	githubScanGistComments  = githubScan.Flag("gist-comments", "Include gist comments in scan.").Bool()

	gitlabScan = cli.Command("gitlab", "Find credentials in GitLab repositories.")
	// TODO: Add more GitLab options
	gitlabScanEndpoint     = gitlabScan.Flag("endpoint", "GitLab endpoint.").Default("https://gitlab.com").String()
	gitlabScanRepos        = gitlabScan.Flag("repo", "GitLab repo url. You can repeat this flag. Leave empty to scan all repos accessible with provided credential. Example: https://gitlab.com/org/repo.git").Strings()
	gitlabScanToken        = gitlabScan.Flag("token", "GitLab token. Can be provided with environment variable GITLAB_TOKEN.").Envar("GITLAB_TOKEN").Required().String()
	gitlabScanIncludePaths = gitlabScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitlabScanExcludePaths = gitlabScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	filesystemScan  = cli.Command("filesystem", "Find credentials in a filesystem.")
	filesystemPaths = filesystemScan.Arg("path", "Path to file or directory to scan.").Strings()
	// DEPRECATED: --directory is deprecated in favor of arguments.
	filesystemDirectories = filesystemScan.Flag("directory", "Path to directory to scan. You can repeat this flag.").Strings()
	// TODO: Add more filesystem scan options. Currently only supports scanning a list of directories.
	// filesystemScanRecursive = filesystemScan.Flag("recursive", "Scan recursively.").Short('r').Bool()
	filesystemScanIncludePaths = filesystemScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	filesystemScanExcludePaths = filesystemScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	s3Scan              = cli.Command("s3", "Find credentials in S3 buckets.")
	s3ScanKey           = s3Scan.Flag("key", "S3 key used to authenticate. Can be provided with environment variable AWS_ACCESS_KEY_ID.").Envar("AWS_ACCESS_KEY_ID").String()
	s3ScanRoleArns      = s3Scan.Flag("role-arn", "Specify the ARN of an IAM role to assume for scanning. You can repeat this flag.").Strings()
	s3ScanSecret        = s3Scan.Flag("secret", "S3 secret used to authenticate. Can be provided with environment variable AWS_SECRET_ACCESS_KEY.").Envar("AWS_SECRET_ACCESS_KEY").String()
	s3ScanSessionToken  = s3Scan.Flag("session-token", "S3 session token used to authenticate temporary credentials. Can be provided with environment variable AWS_SESSION_TOKEN.").Envar("AWS_SESSION_TOKEN").String()
	s3ScanCloudEnv      = s3Scan.Flag("cloud-environment", "Use IAM credentials in cloud environment.").Bool()
	s3ScanBuckets       = s3Scan.Flag("bucket", "Name of S3 bucket to scan. You can repeat this flag. Incompatible with --ignore-bucket.").Strings()
	s3ScanIgnoreBuckets = s3Scan.Flag("ignore-bucket", "Name of S3 bucket to ignore. You can repeat this flag. Incompatible with --bucket.").Strings()
	s3ScanMaxObjectSize = s3Scan.Flag("max-object-size", "Maximum size of objects to scan. Objects larger than this will be skipped. (Byte units eg. 512B, 2KB, 4MB)").Default("250MB").Bytes()

	gcsScan           = cli.Command("gcs", "Find credentials in GCS buckets.")
	gcsProjectID      = gcsScan.Flag("project-id", "GCS project ID used to authenticate. Can NOT be used with unauth scan. Can be provided with environment variable GOOGLE_CLOUD_PROJECT.").Envar("GOOGLE_CLOUD_PROJECT").String()
	gcsCloudEnv       = gcsScan.Flag("cloud-environment", "Use Application Default Credentials, IAM credentials to authenticate.").Bool()
	gcsServiceAccount = gcsScan.Flag("service-account", "Path to GCS service account JSON file.").ExistingFile()
	gcsWithoutAuth    = gcsScan.Flag("without-auth", "Scan GCS buckets without authentication. This will only work for public buckets").Bool()
	gcsAPIKey         = gcsScan.Flag("api-key", "GCS API key used to authenticate. Can be provided with environment variable GOOGLE_API_KEY.").Envar("GOOGLE_API_KEY").String()
	gcsIncludeBuckets = gcsScan.Flag("include-buckets", "Buckets to scan. Comma separated list of buckets. You can repeat this flag. Globs are supported").Short('I').Strings()
	gcsExcludeBuckets = gcsScan.Flag("exclude-buckets", "Buckets to exclude from scan. Comma separated list of buckets. Globs are supported").Short('X').Strings()
	gcsIncludeObjects = gcsScan.Flag("include-objects", "Objects to scan. Comma separated list of objects. you can repeat this flag. Globs are supported").Short('i').Strings()
	gcsExcludeObjects = gcsScan.Flag("exclude-objects", "Objects to exclude from scan. Comma separated list of objects. You can repeat this flag. Globs are supported").Short('x').Strings()
	gcsMaxObjectSize  = gcsScan.Flag("max-object-size", "Maximum size of objects to scan. Objects larger than this will be skipped. (Byte units eg. 512B, 2KB, 4MB)").Default("10MB").Bytes()

	syslogScan     = cli.Command("syslog", "Scan syslog")
	syslogAddress  = syslogScan.Flag("address", "Address and port to listen on for syslog. Example: 127.0.0.1:514").String()
	syslogProtocol = syslogScan.Flag("protocol", "Protocol to listen on. udp or tcp").String()
	syslogTLSCert  = syslogScan.Flag("cert", "Path to TLS cert.").String()
	syslogTLSKey   = syslogScan.Flag("key", "Path to TLS key.").String()
	syslogFormat   = syslogScan.Flag("format", "Log format. Can be rfc3164 or rfc5424").String()

	circleCiScan      = cli.Command("circleci", "Scan CircleCI")
	circleCiScanToken = circleCiScan.Flag("token", "CircleCI token. Can also be provided with environment variable").Envar("CIRCLECI_TOKEN").Required().String()

	dockerScan       = cli.Command("docker", "Scan Docker Image")
	dockerScanImages = dockerScan.Flag("image", "Docker image to scan. Use the file:// prefix to point to a local tarball, otherwise a image registry is assumed.").Required().Strings()

	travisCiScan      = cli.Command("travisci", "Scan TravisCI")
	travisCiScanToken = travisCiScan.Flag("token", "TravisCI token. Can also be provided with environment variable").Envar("TRAVISCI_TOKEN").Required().String()

	// Postman is hidden for now until we get more feedback from the community.
	postmanScan                = cli.Command("postman", "Scan Postman")
	postmanToken               = postmanScan.Flag("token", "Postman token. Can also be provided with environment variable").Envar("POSTMAN_TOKEN").String()
	postmanWorkspaces          = postmanScan.Flag("workspace", "Postman workspace to scan. You can repeat this flag.").Strings()
	postmanCollections         = postmanScan.Flag("collection", "Postman collection to scan. You can repeat this flag.").Strings()
	postmanEnvironments        = postmanScan.Flag("environment", "Postman environment to scan. You can repeat this flag.").Strings()
	postmanIncludeCollections  = postmanScan.Flag("include-collections", "Collections to include in scan. You can repeat this flag.").Strings()
	postmanIncludeEnvironments = postmanScan.Flag("include-environments", "Environments to include in scan. You can repeat this flag.").Strings()
	postmanExcludeCollections  = postmanScan.Flag("exclude-collections", "Collections to exclude from scan. You can repeat this flag.").Strings()
	postmanExcludeEnvironments = postmanScan.Flag("exclude-environments", "Environments to exclude from scan. You can repeat this flag.").Strings()
	postmanWorkspacePaths      = postmanScan.Flag("workspace-paths", "Path to Postman workspaces.").Strings()
	postmanCollectionPaths     = postmanScan.Flag("collection-paths", "Path to Postman collections.").Strings()
	postmanEnvironmentPaths    = postmanScan.Flag("environment-paths", "Path to Postman environments.").Strings()
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

	// Support -h for help
	cli.HelpFlag.Short('h')

	if len(os.Args) <= 1 && isatty.IsTerminal(os.Stdout.Fd()) {
		args := tui.Run()
		if len(args) == 0 {
			os.Exit(0)
		}

		// Overwrite the Args slice so overseer works properly.
		os.Args = os.Args[:1]
		os.Args = append(os.Args, args...)
	}

	cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))

	switch {
	case *trace:
		log.SetLevel(5)
	case *debug:
		log.SetLevel(2)
	}
}

func main() {
	// setup logger
	logFormat := log.WithConsoleSink
	if *jsonOut {
		logFormat = log.WithJSONSink
	}
	logger, sync := log.New("trufflehog", logFormat(os.Stderr))
	// make it the default logger for contexts
	context.SetDefaultLogger(logger)

	if *localDev {
		run(overseer.State{})
		os.Exit(0)
	}

	defer func() { _ = sync() }()
	logFatal := logFatalFunc(logger)

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
		logFatal(err, "error occurred with trufflehog updater 🐷")
	}
}

func run(state overseer.State) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	go func() {
		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			ctx.Logger().Error(err, "error cleaning temporary artifacts")
		}
	}()

	logger := ctx.Logger()
	logFatal := logFatalFunc(logger)

	killSignal := make(chan os.Signal, 1)
	signal.Notify(killSignal, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-killSignal
		logger.Info("Received signal, shutting down.")
		cancel(fmt.Errorf("canceling context due to signal"))

		if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
			logger.Error(err, "error cleaning temporary artifacts")
		} else {
			logger.Info("cleaned temporary artifacts")
		}

		time.Sleep(time.Second * 10)
		logger.Info("10 seconds elapsed. Forcing shutdown.")
		os.Exit(0)
	}()

	logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))

	if *githubScanToken != "" {
		// NOTE: this kludge is here to do an authenticated shallow commit
		// TODO: refactor to better pass credentials
		os.Setenv("GITHUB_TOKEN", *githubScanToken)
	}

	// When setting a base commit, chunks must be scanned in order.
	if *gitScanSinceCommit != "" {
		*concurrency = 1
	}

	if *profile {
		go func() {
			router := http.NewServeMux()
			router.Handle("/debug/pprof/", http.DefaultServeMux)
			router.Handle("/debug/fgprof", fgprof.Handler())
			logger.Info("starting pprof and fgprof server on :18066 /debug/pprof and /debug/fgprof")
			if err := http.ListenAndServe(":18066", router); err != nil {
				logger.Error(err, "error serving pprof and fgprof")
			}
		}()
	}

	conf := &config.Config{}
	if *configFilename != "" {
		var err error
		conf, err = config.Read(*configFilename)
		if err != nil {
			logFatal(err, "error parsing the provided configuration file")
		}
	}

	if *archiveMaxSize != 0 {
		handlers.SetArchiveMaxSize(int(*archiveMaxSize))
	}
	if *archiveMaxDepth != 0 {
		handlers.SetArchiveMaxDepth(*archiveMaxDepth)
	}
	if *archiveTimeout != 0 {
		handlers.SetArchiveMaxTimeout(*archiveTimeout)
	}

	// Build include and exclude detector sets for filtering on engine initialization.
	// Exit if there was an error to inform the user of the misconfiguration.
	var includeDetectorSet, excludeDetectorSet map[config.DetectorID]struct{}
	var detectorsWithCustomVerifierEndpoints map[config.DetectorID][]string
	{
		includeList, err := config.ParseDetectors(*includeDetectors)
		if err != nil {
			logFatal(err, "invalid include list detector configuration")
		}
		excludeList, err := config.ParseDetectors(*excludeDetectors)
		if err != nil {
			logFatal(err, "invalid exclude list detector configuration")
		}
		detectorsWithCustomVerifierEndpoints, err = config.ParseVerifierEndpoints(*verifiers)
		if err != nil {
			logFatal(err, "invalid verifier detector configuration")
		}
		includeDetectorSet = detectorTypeToSet(includeList)
		excludeDetectorSet = detectorTypeToSet(excludeList)
	}

	// Verify that all the user-provided detectors support the optional
	// detector features.
	{
		if err, id := verifyDetectorsAreVersioner(includeDetectorSet); err != nil {
			logFatal(err, "invalid include list detector configuration", "detector", id)
		}
		if err, id := verifyDetectorsAreVersioner(excludeDetectorSet); err != nil {
			logFatal(err, "invalid exclude list detector configuration", "detector", id)
		}
		if err, id := verifyDetectorsAreVersioner(detectorsWithCustomVerifierEndpoints); err != nil {
			logFatal(err, "invalid verifier detector configuration", "detector", id)
		}
		// Extra check for endpoint customization.
		isEndpointCustomizer := engine.DefaultDetectorTypesImplementing[detectors.EndpointCustomizer]()
		for id := range detectorsWithCustomVerifierEndpoints {
			if _, ok := isEndpointCustomizer[id.ID]; !ok {
				logFatal(
					fmt.Errorf("endpoint provided but detector does not support endpoint customization"),
					"invalid custom verifier endpoint detector configuration",
					"detector", id,
				)
			}
		}
	}

	includeFilter := func(d detectors.Detector) bool {
		_, ok := getWithDetectorID(d, includeDetectorSet)
		return ok
	}
	excludeFilter := func(d detectors.Detector) bool {
		_, ok := getWithDetectorID(d, excludeDetectorSet)
		return !ok
	}
	// Abuse filter to cause a side-effect.
	endpointCustomizer := func(d detectors.Detector) bool {
		urls, ok := getWithDetectorID(d, detectorsWithCustomVerifierEndpoints)
		if !ok {
			return true
		}
		id := config.GetDetectorID(d)
		customizer, ok := d.(detectors.EndpointCustomizer)
		if !ok {
			// NOTE: We should never reach here due to validation above.
			logFatal(
				fmt.Errorf("failed to configure a detector endpoint"),
				"the provided detector does not support endpoint configuration",
				"detector", id,
			)
		}
		if !*customVerifiersOnly || len(urls) == 0 {
			urls = append(urls, customizer.DefaultEndpoint())
		}
		if err := customizer.SetEndpoints(urls...); err != nil {
			logFatal(err, "failed configuring custom endpoint for detector", "detector", id)
		}
		logger.Info("configured detector with verification urls",
			"detector", id, "urls", urls,
		)
		return true
	}

	// Set how the engine will print its results.
	var printer engine.Printer
	switch {
	case *jsonLegacy:
		printer = new(output.LegacyJSONPrinter)
	case *jsonOut:
		printer = new(output.JSONPrinter)
	case *gitHubActionsFormat:
		printer = new(output.GitHubActionsPrinter)
	default:
		printer = new(output.PlainPrinter)
	}

	if !*jsonLegacy && !*jsonOut {
		fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")
	}

	var jobReportWriter io.WriteCloser
	if *jobReportFile != nil {
		jobReportWriter = *jobReportFile
	}

	// Parse --results flag.
	if *onlyVerified {
		r := "verified"
		results = &r
	}
	parsedResults, err := parseResults(results)
	if err != nil {
		logFatal(err, "failed to configure results flag")
	}

	e, err := engine.Start(ctx,
		engine.WithConcurrency(*concurrency),
		engine.WithDecoders(decoders.DefaultDecoders()...),
		engine.WithDetectors(engine.DefaultDetectors()...),
		engine.WithDetectors(conf.Detectors...),
		engine.WithVerify(!*noVerification),
		engine.WithFilterDetectors(includeFilter),
		engine.WithFilterDetectors(excludeFilter),
		engine.WithFilterDetectors(endpointCustomizer),
		engine.WithFilterUnverified(*filterUnverified),
		engine.WithResults(parsedResults),
		engine.WithPrintAvgDetectorTime(*printAvgDetectorTime),
		engine.WithPrinter(printer),
		engine.WithFilterEntropy(*filterEntropy),
		engine.WithVerificationOverlap(*allowVerificationOverlap),
		engine.WithJobReportWriter(jobReportWriter),
	)
	if err != nil {
		logFatal(err, "error initializing engine")
	}

	switch cmd {
	case gitScan.FullCommand():
		cfg := sources.GitConfig{
			URI:              *gitScanURI,
			IncludePathsFile: *gitScanIncludePaths,
			ExcludePathsFile: *gitScanExcludePaths,
			HeadRef:          *gitScanBranch,
			BaseRef:          *gitScanSinceCommit,
			MaxDepth:         *gitScanMaxDepth,
			Bare:             *gitScanBare,
			ExcludeGlobs:     *gitScanExcludeGlobs,
		}
		if err = e.ScanGit(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan Git.")
		}
	case githubScan.FullCommand():
		filter, err := common.FilterFromFiles(*githubScanIncludePaths, *githubScanExcludePaths)
		if err != nil {
			logFatal(err, "could not create filter")
		}
		if len(*githubScanOrgs) == 0 && len(*githubScanRepos) == 0 {
			logFatal(fmt.Errorf("invalid config"), "You must specify at least one organization or repository.")
		}

		cfg := sources.GithubConfig{
			Endpoint:                   *githubScanEndpoint,
			Token:                      *githubScanToken,
			IncludeForks:               *githubIncludeForks,
			IncludeMembers:             *githubIncludeMembers,
			IncludeWikis:               *githubIncludeWikis,
			Concurrency:                *concurrency,
			ExcludeRepos:               *githubExcludeRepos,
			IncludeRepos:               *githubIncludeRepos,
			Repos:                      *githubScanRepos,
			Orgs:                       *githubScanOrgs,
			IncludeIssueComments:       *githubScanIssueComments,
			IncludePullRequestComments: *githubScanPRComments,
			IncludeGistComments:        *githubScanGistComments,
			Filter:                     filter,
		}
		if err := e.ScanGitHub(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan Github.")
		}
	case gitlabScan.FullCommand():
		filter, err := common.FilterFromFiles(*gitlabScanIncludePaths, *gitlabScanExcludePaths)
		if err != nil {
			logFatal(err, "could not create filter")
		}

		cfg := sources.GitlabConfig{
			Endpoint: *gitlabScanEndpoint,
			Token:    *gitlabScanToken,
			Repos:    *gitlabScanRepos,
			Filter:   filter,
		}
		if err := e.ScanGitLab(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan GitLab.")
		}
	case filesystemScan.FullCommand():
		if len(*filesystemDirectories) > 0 {
			ctx.Logger().Info("--directory flag is deprecated, please pass directories as arguments")
		}
		paths := make([]string, 0, len(*filesystemPaths)+len(*filesystemDirectories))
		paths = append(paths, *filesystemPaths...)
		paths = append(paths, *filesystemDirectories...)
		cfg := sources.FilesystemConfig{
			Paths:            paths,
			IncludePathsFile: *filesystemScanIncludePaths,
			ExcludePathsFile: *filesystemScanExcludePaths,
		}
		if err = e.ScanFileSystem(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan filesystem")
		}
	case s3Scan.FullCommand():
		cfg := sources.S3Config{
			Key:           *s3ScanKey,
			Secret:        *s3ScanSecret,
			SessionToken:  *s3ScanSessionToken,
			Buckets:       *s3ScanBuckets,
			IgnoreBuckets: *s3ScanIgnoreBuckets,
			Roles:         *s3ScanRoleArns,
			CloudCred:     *s3ScanCloudEnv,
			MaxObjectSize: int64(*s3ScanMaxObjectSize),
		}
		if err := e.ScanS3(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan S3.")
		}
	case syslogScan.FullCommand():
		cfg := sources.SyslogConfig{
			Address:     *syslogAddress,
			Format:      *syslogFormat,
			Protocol:    *syslogProtocol,
			CertPath:    *syslogTLSCert,
			KeyPath:     *syslogTLSKey,
			Concurrency: *concurrency,
		}
		if err := e.ScanSyslog(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan syslog.")
		}
	case circleCiScan.FullCommand():
		if err := e.ScanCircleCI(ctx, *circleCiScanToken); err != nil {
			logFatal(err, "Failed to scan CircleCI.")
		}
	case travisCiScan.FullCommand():
		if err := e.ScanTravisCI(ctx, *travisCiScanToken); err != nil {
			logFatal(err, "Failed to scan TravisCI.")
		}
	case gcsScan.FullCommand():
		cfg := sources.GCSConfig{
			ProjectID:      *gcsProjectID,
			CloudCred:      *gcsCloudEnv,
			ServiceAccount: *gcsServiceAccount,
			WithoutAuth:    *gcsWithoutAuth,
			ApiKey:         *gcsAPIKey,
			IncludeBuckets: commaSeparatedToSlice(*gcsIncludeBuckets),
			ExcludeBuckets: commaSeparatedToSlice(*gcsExcludeBuckets),
			IncludeObjects: commaSeparatedToSlice(*gcsIncludeObjects),
			ExcludeObjects: commaSeparatedToSlice(*gcsExcludeObjects),
			Concurrency:    *concurrency,
			MaxObjectSize:  int64(*gcsMaxObjectSize),
		}
		if err := e.ScanGCS(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan GCS.")
		}
	case dockerScan.FullCommand():
		dockerConn := sourcespb.Docker{
			Images: *dockerScanImages,
			Credential: &sourcespb.Docker_DockerKeychain{
				DockerKeychain: true,
			},
		}
		anyConn, err := anypb.New(&dockerConn)
		if err != nil {
			logFatal(err, "Failed to marshal Docker connection")
		}
		if err := e.ScanDocker(ctx, anyConn); err != nil {
			logFatal(err, "Failed to scan Docker.")
		}
	case postmanScan.FullCommand():
		cfg := sources.PostmanConfig{
			Token:               *postmanToken,
			Workspaces:          *postmanWorkspaces,
			Collections:         *postmanCollections,
			Environments:        *postmanEnvironments,
			IncludeCollections:  *postmanIncludeCollections,
			IncludeEnvironments: *postmanIncludeEnvironments,
			ExcludeCollections:  *postmanExcludeCollections,
			ExcludeEnvironments: *postmanExcludeEnvironments,
			CollectionPaths:     *postmanCollectionPaths,
			WorkspacePaths:      *postmanWorkspacePaths,
			EnvironmentPaths:    *postmanEnvironmentPaths,
		}
		if err := e.ScanPostman(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan Postman.")
		}
	}

	// Wait for all workers to finish.
	if err = e.Finish(ctx); err != nil {
		logFatal(err, "engine failed to finish execution")
	}
	if err := cleantemp.CleanTempArtifacts(ctx); err != nil {
		ctx.Logger().Error(err, "error cleaning temp artifacts")
	}

	metrics := e.GetMetrics()
	// Print results.
	logger.Info("finished scanning",
		"chunks", metrics.ChunksScanned,
		"bytes", metrics.BytesScanned,
		"verified_secrets", metrics.VerifiedSecretsFound,
		"unverified_secrets", metrics.UnverifiedSecretsFound,
		"scan_duration", metrics.ScanDuration.String(),
	)

	if *printAvgDetectorTime {
		printAverageDetectorTime(e)
	}

	if e.HasFoundResults() && *fail {
		logger.V(2).Info("exiting with code 183 because results were found")
		os.Exit(183)
	}
}

// parseResults ensures that users provide valid CSV input to `--results`.
//
// This is a work-around to kingpin not supporting CSVs.
// See: https://github.com/trufflesecurity/trufflehog/pull/2372#issuecomment-1983868917
func parseResults(input *string) (map[string]struct{}, error) {
	if *input == "" {
		return nil, nil
	}

	var (
		values  = strings.Split(strings.ToLower(*input), ",")
		results = make(map[string]struct{}, 3)
	)
	for _, value := range values {
		switch value {
		case "verified", "unknown", "unverified":
			results[value] = struct{}{}
		default:
			return nil, fmt.Errorf("invalid value '%s', valid values are 'verified,unknown,unverified'", value)
		}
	}
	return results, nil
}

// logFatalFunc returns a log.Fatal style function. Calling the returned
// function will terminate the program without cleanup.
func logFatalFunc(logger logr.Logger) func(error, string, ...any) {
	return func(err error, message string, keyAndVals ...any) {
		logger.Error(err, message, keyAndVals...)
		if err != nil {
			os.Exit(1)
			return
		}
		os.Exit(0)
	}
}

func commaSeparatedToSlice(s []string) []string {
	var result []string
	for _, items := range s {
		for _, item := range strings.Split(items, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			result = append(result, item)
		}
	}
	return result
}

func printAverageDetectorTime(e *engine.Engine) {
	fmt.Fprintln(os.Stderr, "Average detector time is the measurement of average time spent on each detector when results are returned.")
	for detectorName, duration := range e.GetDetectorsMetrics() {
		fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, duration)
	}
}

// detectorTypeToSet is a helper function to convert a slice of detector IDs into a set.
func detectorTypeToSet(detectors []config.DetectorID) map[config.DetectorID]struct{} {
	out := make(map[config.DetectorID]struct{}, len(detectors))
	for _, d := range detectors {
		out[d] = struct{}{}
	}
	return out
}

// getWithDetectorID is a helper function to get a value from a map using a
// detector's ID. This function behaves like a normal map lookup, with an extra
// step of checking for the non-specific version of a detector.
func getWithDetectorID[T any](d detectors.Detector, data map[config.DetectorID]T) (T, bool) {
	key := config.GetDetectorID(d)
	// Check if the specific ID is provided.
	if t, ok := data[key]; ok || key.Version == 0 {
		return t, ok
	}
	// Check if the generic type is provided without a version.
	// This means "all" versions of a type.
	key.Version = 0
	t, ok := data[key]
	return t, ok
}

// verifyDetectorsAreVersioner checks all keys in a provided map to verify the
// provided type is actually a Versioner.
func verifyDetectorsAreVersioner[T any](data map[config.DetectorID]T) (error, config.DetectorID) {
	isVersioner := engine.DefaultDetectorTypesImplementing[detectors.Versioner]()
	for id := range data {
		if id.Version == 0 {
			// Version not provided.
			continue
		}
		if _, ok := isVersioner[id.ID]; ok {
			// Version provided for a Versioner detector.
			continue
		}
		// Version provided on a non-Versioner detector.
		return fmt.Errorf("version provided but detector does not have a version"), id
	}
	return nil, config.DetectorID{}
}
