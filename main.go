package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/felixge/fgprof"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func main() {
	cli := kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
	debug := cli.Flag("debug", "Run in debug mode").Bool()
	jsonOut := cli.Flag("json", "Output in JSON format.").Short('j').Bool()
	jsonLegacy := cli.Flag("json-legacy", "Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.").Bool()
	concurrency := cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()
	noVerification := cli.Flag("no-verification", "Don't verify the results.").Bool()
	onlyVerified := cli.Flag("only-verified", "Only output verified results.").Bool()
	// rules := cli.Flag("rules", "Path to file with custom rules.").String()
	printAvgDetectorTime := cli.Flag("print-avg-detector-time", "Print the average time spent on each detector.").Bool()

	gitScan := cli.Command("git", "Find credentials in git repositories.")
	gitScanURI := gitScan.Arg("uri", "Git repository URL. https:// or file:// schema expected.").Required().String()
	gitScanIncludePaths := gitScan.Flag("include_paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitScanExcludePaths := gitScan.Flag("exclude_paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	gitScanSinceCommit := gitScan.Flag("since_commit", "Commit to start scan from.").String()
	gitScanBranch := gitScan.Flag("branch", "Branch to scan.").String()
	gitScanMaxDepth := gitScan.Flag("max_depth", "Maximum depth of commits to scan.").Int()
	gitScan.Flag("allow", "No-op flag for backwards compat.").Bool()
	gitScan.Flag("entropy", "No-op flag for backwards compat.").Bool()
	gitScan.Flag("regex", "No-op flag for backwards compat.").Bool()

	githubScan := cli.Command("github", "Find credentials in GitHub repositories.")
	githubScanEndpoint := githubScan.Flag("endpoint", "GitHub endpoint.").Default("https://api.github.com").String()
	githubScanRepos := githubScan.Flag("repo", `GitHub repository to scan. You can repeat this flag. Example: "https://github.com/dustin-decker/secretsandstuff"`).Strings()
	githubScanOrgs := githubScan.Flag("org", `GitHub organization to scan. You can repeat this flag. Example: "trufflesecurity"`).Strings()
	githubScanToken := githubScan.Flag("token", "GitHub token.").String()
	githubIncludeForks := githubScan.Flag("include_forks", "Include forks in scan.").Bool()

	gitlabScan := cli.Command("gitlab", "Find credentials in GitLab repositories.")
	// TODO: Add more GitLab options
	gitlabScanEndpoint := gitlabScan.Flag("endpoint", "GitLab endpoint.").Default("https://gitlab.com").String()
	gitlabScanRepos := gitlabScan.Flag("repo", "GitLab repo url. You can repeat this flag. Leave empty to scan all repos accessible with provided credential. Example: https://gitlab.com/org/repo.git").Strings()
	gitlabScanToken := gitlabScan.Flag("token", "GitLab token.").Required().String()

	filesystemScan := cli.Command("filesystem", "Find credentials in a filesystem.")
	filesystemDirectories := filesystemScan.Flag("directory", "Path to directory to scan. You can repeat this flag.").Required().Strings()
	// TODO: Add more filesystem scan options. Currently only supports scanning a list of directories.
	// filesystemScanRecursive := filesystemScan.Flag("recursive", "Scan recursively.").Short('r').Bool()
	// filesystemScanIncludePaths := filesystemScan.Flag("include_paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	// filesystemScanExcludePaths := filesystemScan.Flag("exclude_paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	s3Scan := cli.Command("s3", "Coming soon. Find credentials in an S3 bucket.")

	cmd := kingpin.MustParse(cli.Parse(os.Args[1:]))

	// When setting a base commit, chunks must be scanned in order.
	if *gitScanSinceCommit != "" {
		*concurrency = 1
	}

	if *jsonOut {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
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
	switch cmd {
	case gitScan.FullCommand():
		var remote bool
		repoPath, remote, err = git.PrepareRepo(*gitScanURI)
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
		err = e.ScanGitHub(ctx, *githubScanEndpoint, *githubScanRepos, *githubScanOrgs, *githubScanToken, *githubIncludeForks, filter, *concurrency)
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
		log.Fatal("S3 not implemented. Coming soon.")
	}

	if !*jsonLegacy && !*jsonOut {
		fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")
	}

	foundResults := false
	for r := range e.ResultsChan() {
		if *onlyVerified && !r.Verified {
			continue
		}
		foundResults = true

		switch {
		case *jsonLegacy:
			legacy := output.ConvertToLegacyJSON(&r, repoPath)
			out, err := json.Marshal(legacy)
			if err != nil {
				logrus.WithError(err).Fatal("could not marshal result")
			}
			fmt.Println(string(out))
		case *jsonOut:
			out, err := json.Marshal(r)
			if err != nil {
				logrus.WithError(err).Fatal("could not marshal result")
			}
			fmt.Println(string(out))
		default:
			output.PrintPlainOutput(&r)
		}
	}
	logrus.Debugf("scanned %d chunks", e.ChunksScanned())

	if *printAvgDetectorTime {
		printAverageDetectorTime(e)
	}

	if foundResults {
		os.Exit(1)
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
