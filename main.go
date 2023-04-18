package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/felixge/fgprof"
	"github.com/go-logr/logr"
	"github.com/gorilla/mux"
	"github.com/jpillora/overseer"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/updater"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

var (
	cli                 = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
	cmd                 string
	debug               = cli.Flag("debug", "Run in debug mode.").Bool()
	trace               = cli.Flag("trace", "Run in trace mode.").Bool()
	profile             = cli.Flag("profile", "Enables profiling and sets a pprof and fgprof server on :18066.").Bool()
	jsonOut             = cli.Flag("json", "Output in JSON format.").Short('j').Bool()
	jsonLegacy          = cli.Flag("json-legacy", "Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.").Bool()
	gitHubActionsFormat = cli.Flag("github-actions", "Output in GitHub Actions format.").Bool()
	concurrency         = cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()
	noVerification      = cli.Flag("no-verification", "Don't verify the results.").Bool()
	onlyVerified        = cli.Flag("only-verified", "Only output verified results.").Bool()
	filterUnverified    = cli.Flag("filter-unverified", "Only output first unverified result per chunk per detector if there are more than one results.").Bool()
	configFilename      = cli.Flag("config", "Path to configuration file.").ExistingFile()
	// rules = cli.Flag("rules", "Path to file with custom rules.").String()
	printAvgDetectorTime = cli.Flag("print-avg-detector-time", "Print the average time spent on each detector.").Bool()
	noUpdate             = cli.Flag("no-update", "Don't check for updates.").Bool()
	fail                 = cli.Flag("fail", "Exit with code 183 if results are found.").Bool()
	verifiers            = cli.Flag("verifier", "Set custom verification endpoints.").StringMap()
	archiveMaxSize       = cli.Flag("archive-max-size", "Maximum size of archive to scan. (Byte units eg. 512B, 2KB, 4MB)").Bytes()
	archiveMaxDepth      = cli.Flag("archive-max-depth", "Maximum depth of archive to scan.").Int()
	archiveTimeout       = cli.Flag("archive-timeout", "Maximum time to spend extracting an archive.").Duration()
	includeDetectors     = cli.Flag("include-detectors", "Comma separated list of detector types to include. Protobuf name or IDs may be used, as well as ranges.").Default("all").String()
	excludeDetectors     = cli.Flag("exclude-detectors", "Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.").String()

	gitScan             = cli.Command("git", "Find credentials in git repositories.")
	gitScanURI          = gitScan.Arg("uri", "Git repository URL. https://, file://, or ssh:// schema expected.").Required().String()
	gitScanIncludePaths = gitScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitScanExcludePaths = gitScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	gitScanExcludeGlobs = gitScan.Flag("exclude-globs", "Comma separated list of globs to exclude in scan. This option filters at the `git log` level, resulting in faster scans.").String()
	gitScanSinceCommit  = gitScan.Flag("since-commit", "Commit to start scan from.").String()
	gitScanBranch       = gitScan.Flag("branch", "Branch to scan.").String()
	gitScanMaxDepth     = gitScan.Flag("max-depth", "Maximum depth of commits to scan.").Int()
	_                   = gitScan.Flag("allow", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("entropy", "No-op flag for backwards compat.").Bool()
	_                   = gitScan.Flag("regex", "No-op flag for backwards compat.").Bool()

	githubScan             = cli.Command("github", "Find credentials in GitHub repositories.")
	githubScanEndpoint     = githubScan.Flag("endpoint", "GitHub endpoint.").Default("https://api.github.com").String()
	githubScanRepos        = githubScan.Flag("repo", `GitHub repository to scan. You can repeat this flag. Example: "https://github.com/dustin-decker/secretsandstuff"`).Strings()
	githubScanOrgs         = githubScan.Flag("org", `GitHub organization to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	githubScanToken        = githubScan.Flag("token", "GitHub token. Can be provided with environment variable GITHUB_TOKEN.").Envar("GITHUB_TOKEN").String()
	githubIncludeForks     = githubScan.Flag("include-forks", "Include forks in scan.").Bool()
	githubIncludeMembers   = githubScan.Flag("include-members", "Include organization member repositories in scan.").Bool()
	githubIncludeRepos     = githubScan.Flag("include-repos", `Repositories to include in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/trufflehog", "trufflesecurity/t*"`).Strings()
	githubExcludeRepos     = githubScan.Flag("exclude-repos", `Repositories to exclude in an org scan. This can also be a glob pattern. You can repeat this flag. Must use Github repo full name. Example: "trufflesecurity/driftwood", "trufflesecurity/d*"`).Strings()
	githubScanIncludePaths = githubScan.Flag("include-paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	githubScanExcludePaths = githubScan.Flag("exclude-paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

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

	s3Scan             = cli.Command("s3", "Find credentials in S3 buckets.")
	s3ScanKey          = s3Scan.Flag("key", "S3 key used to authenticate. Can be provided with environment variable AWS_ACCESS_KEY_ID.").Envar("AWS_ACCESS_KEY_ID").String()
	s3ScanSecret       = s3Scan.Flag("secret", "S3 secret used to authenticate. Can be provided with environment variable AWS_SECRET_ACCESS_KEY.").Envar("AWS_SECRET_ACCESS_KEY").String()
	s3ScanSessionToken = s3Scan.Flag("session-token", "S3 session token used to authenticate temporary credentials. Can be provided with environment variable AWS_SESSION_TOKEN.").Envar("AWS_SESSION_TOKEN").String()
	s3ScanCloudEnv     = s3Scan.Flag("cloud-environment", "Use IAM credentials in cloud environment.").Bool()
	s3ScanBuckets      = s3Scan.Flag("bucket", "Name of S3 bucket to scan. You can repeat this flag.").Strings()

	gcsScan           = cli.Command("gcs", "Find credentials in GCS buckets.")
	gcsProjectID      = gcsScan.Flag("project-id", "GCS project ID used to authenticate. Can NOT be used with unauth scan. Can be provided with environment variable GOOGLE_CLOUD_PROJECT.").Envar("GOOGLE_CLOUD_PROJECT").String()
	gcsCloudEnv       = gcsScan.Flag("cloud-environment", "Use Application Default Credentials, IAM credentials to authenticate.").Bool()
	gcsServiceAccount = gcsScan.Flag("service-account", "Path to GCS service account JSON file.").ExistingFile()
	gcsWithoutAuth    = gcsScan.Flag("without-auth", "Scan GCS buckets without authentication. This will only work for public buckets").Bool()
	gcsAPIKey         = gcsScan.Flag("api-key", "GCS API key used to authenticate. Can be provided with environment variable GOOGLE_API_KEY.").Envar("GOOGLE_API_KEY").String()
	gcsIncludeBuckets = gcsScan.Flag("include-buckets", "Buckets to scan. Comma seperated list of buckets. You can repeat this flag. Globs are supported").Short('I').Strings()
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
		logFatal(err, "error occured with trufflehog updater 🐷")
	}
}

func run(state overseer.State) {
	ctx := context.Background()
	logger := ctx.Logger()
	logFatal := logFatalFunc(logger)

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
			router := mux.NewRouter()
			router.PathPrefix("/debug/pprof").Handler(http.DefaultServeMux)
			router.PathPrefix("/debug/fgprof").Handler(fgprof.Handler())
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

	urls := splitVerifierURLs(*verifiers)

	if *archiveMaxSize != 0 {
		handlers.SetArchiveMaxSize(int(*archiveMaxSize))
	}
	if *archiveMaxDepth != 0 {
		handlers.SetArchiveMaxDepth(*archiveMaxDepth)
	}
	if *archiveTimeout != 0 {
		handlers.SetArchiveMaxTimeout(*archiveTimeout)
	}

	// Build include and exclude detector filter sets.
	var includeDetectorTypes, excludeDetectorTypes map[detectorspb.DetectorType]config.DetectorID
	{
		includeList, err := config.ParseDetectors(*includeDetectors)
		if err != nil {
			// Exit if there was an error to inform the user of the misconfiguration.
			logFatal(err, "invalid include list detector configuration")
		}
		excludeList, err := config.ParseDetectors(*excludeDetectors)
		if err != nil {
			// Exit if there was an error to inform the user of the misconfiguration.
			logFatal(err, "invalid exclude list detector configuration")
		}
		includeDetectorTypes = detectorTypeToMap(includeList)
		excludeDetectorTypes = detectorTypeToMap(excludeList)
	}
	includeFilter := func(d detectors.Detector) bool {
		id, ok := includeDetectorTypes[d.Type()]
		if id.Version == 0 {
			return ok
		}
		versionD, ok := d.(detectors.Versioner)
		if !ok {
			// Error: version provided but not a detectors.Versioner
			logFatal(
				fmt.Errorf("version provided but detector does not have a version"),
				"invalid include list detector configuration",
				"detector", id,
			)
		}
		return versionD.Version() == id.Version
	}
	excludeFilter := func(d detectors.Detector) bool {
		id, ok := excludeDetectorTypes[d.Type()]
		if id.Version == 0 {
			return !ok
		}
		versionD, ok := d.(detectors.Versioner)
		if !ok {
			// Error: version provided but not a detectors.Versioner
			logFatal(
				fmt.Errorf("version provided but detector does not have a version"),
				"invalid exclude list detector configuration",
				"detector", id,
			)
		}
		return versionD.Version() != id.Version
	}

	e := engine.Start(ctx,
		engine.WithConcurrency(*concurrency),
		engine.WithDecoders(decoders.DefaultDecoders()...),
		engine.WithDetectors(!*noVerification, engine.CustomDetectors(ctx, urls)...),
		engine.WithDetectors(!*noVerification, conf.Detectors...),
		engine.WithFilterDetectors(includeFilter),
		engine.WithFilterDetectors(excludeFilter),
		engine.WithFilterUnverified(*filterUnverified),
	)

	var repoPath string
	var remote bool
	switch cmd {
	case gitScan.FullCommand():
		filter, err := common.FilterFromFiles(*gitScanIncludePaths, *gitScanExcludePaths)
		if err != nil {
			logFatal(err, "could not create filter")
		}
		repoPath, remote, err = git.PrepareRepoSinceCommit(ctx, *gitScanURI, *gitScanSinceCommit)
		if err != nil || repoPath == "" {
			logFatal(err, "error preparing git repo for scanning")
		}
		if remote {
			defer os.RemoveAll(repoPath)
		}
		excludedGlobs := []string{}
		if *gitScanExcludeGlobs != "" {
			excludedGlobs = strings.Split(*gitScanExcludeGlobs, ",")
		}

		cfg := sources.GitConfig{
			RepoPath:     repoPath,
			HeadRef:      *gitScanBranch,
			BaseRef:      *gitScanSinceCommit,
			MaxDepth:     *gitScanMaxDepth,
			Filter:       filter,
			ExcludeGlobs: excludedGlobs,
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
			Endpoint:       *githubScanEndpoint,
			Token:          *githubScanToken,
			IncludeForks:   *githubIncludeForks,
			IncludeMembers: *githubIncludeMembers,
			Concurrency:    *concurrency,
			ExcludeRepos:   *githubExcludeRepos,
			IncludeRepos:   *githubIncludeRepos,
			Repos:          *githubScanRepos,
			Orgs:           *githubScanOrgs,
			Filter:         filter,
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
		filter, err := common.FilterFromFiles(*filesystemScanIncludePaths, *filesystemScanExcludePaths)
		if err != nil {
			logFatal(err, "could not create filter")
		}
		if len(*filesystemDirectories) > 0 {
			ctx.Logger().Info("--directory flag is deprecated, please pass directories as arguments")
		}
		paths := make([]string, 0, len(*filesystemPaths)+len(*filesystemDirectories))
		paths = append(paths, *filesystemPaths...)
		paths = append(paths, *filesystemDirectories...)
		cfg := sources.FilesystemConfig{
			Paths:  paths,
			Filter: filter,
		}
		if err = e.ScanFileSystem(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan filesystem")
		}
	case s3Scan.FullCommand():
		cfg := sources.S3Config{
			Key:          *s3ScanKey,
			Secret:       *s3ScanSecret,
			SessionToken: *s3ScanSessionToken,
			Buckets:      *s3ScanBuckets,
			CloudCred:    *s3ScanCloudEnv,
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
	case gcsScan.FullCommand():
		cfg := sources.GCSConfig{
			ProjectID:      *gcsProjectID,
			CloudCred:      *gcsCloudEnv,
			ServiceAccount: *gcsServiceAccount,
			WithoutAuth:    *gcsWithoutAuth,
			ApiKey:         *gcsAPIKey,
			IncludeBuckets: commaSeperatedToSlice(*gcsIncludeBuckets),
			ExcludeBuckets: commaSeperatedToSlice(*gcsExcludeBuckets),
			IncludeObjects: commaSeperatedToSlice(*gcsIncludeObjects),
			ExcludeObjects: commaSeperatedToSlice(*gcsExcludeObjects),
			Concurrency:    *concurrency,
			MaxObjectSize:  int64(*gcsMaxObjectSize),
		}
		if err := e.ScanGCS(ctx, cfg); err != nil {
			logFatal(err, "Failed to scan GCS.")
		}
	}
	// asynchronously wait for scanning to finish and cleanup
	go e.Finish(ctx)

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

		var err error
		switch {
		case *jsonLegacy:
			err = output.PrintLegacyJSON(ctx, &r)
		case *jsonOut:
			err = output.PrintJSON(&r)
		case *gitHubActionsFormat:
			err = output.PrintGitHubActionsOutput(&r)
		default:
			err = output.PrintPlainOutput(&r)
		}
		if err != nil {
			logFatal(err, "error printing results")
		}
	}
	logger.V(2).Info("finished scanning",
		"chunks", e.ChunksScanned(),
		"bytes", e.BytesScanned(),
	)

	if *printAvgDetectorTime {
		printAverageDetectorTime(e)
	}

	if foundResults && *fail {
		logger.V(2).Info("exiting with code 183 because results were found")
		os.Exit(183)
	}
}

func commaSeperatedToSlice(s []string) []string {
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
	for detectorName, durations := range e.DetectorAvgTime() {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(len(durations))
		fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, avgDuration)
	}
}

func splitVerifierURLs(verifierURLs map[string]string) map[string][]string {
	verifiers := make(map[string][]string, len(verifierURLs))
	for k, v := range verifierURLs {
		key := strings.ToLower(k)
		sliceOfValues := strings.Split(v, ",")
		for i, s := range sliceOfValues {
			sliceOfValues[i] = strings.TrimSpace(s)
		}
		verifiers[key] = sliceOfValues
	}
	return verifiers
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

func detectorTypeToMap(detectors []config.DetectorID) map[detectorspb.DetectorType]config.DetectorID {
	output := make(map[detectorspb.DetectorType]config.DetectorID, len(detectors))
	for _, d := range detectors {
		output[d.ID] = d
	}
	return output
}
