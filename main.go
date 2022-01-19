package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"

	"github.com/trufflesecurity/trufflehog/pkg/common"
	"github.com/trufflesecurity/trufflehog/pkg/sources/git"

	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/pkg/engine"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func main() {

	cli := kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
	debug := cli.Flag("debug", "Run in debug mode").Bool()
	jsonOut := cli.Flag("json", "Output in JSON format.").Short('j').Bool()
	concurrency := cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()
	noVerification := cli.Flag("no-verification", "Don't verify the results.").Bool()
	// rules := cli.Flag("rules", "Path to file with custom rules.").String()

	gitScan := cli.Command("git", "Find credentials in git repositories.")
	gitScanURI := gitScan.Arg("uri", "Git repository URL. https:// or file:// schema expected.").Required().String()
	gitScanIncludePaths := gitScan.Flag("include_paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	gitScanExcludePaths := gitScan.Flag("exclude_paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()
	// gitScanSinceCommit := gitScan.Flag("since_commit", "Commit to start scan from.").String()
	gitScanBranch := gitScan.Flag("branch", "Branch to scan.").String()
	// gitScanMaxDepth := gitScan.Flag("max_depth", "Maximum depth of commits to scan.").Int()
	gitScan.Flag("allow", "No-op flag for backwards compat.").Bool()
	gitScan.Flag("entropy", "No-op flag for backwards compat.").Bool()
	gitScan.Flag("regex", "No-op flag for backwards compat.").Bool()

	githubScan := cli.Command("github", "Find credentials in GitHub repositories.")
	// githubScanTarget := githubScan.Arg("target", "GitHub target. Can be a repository, user or organization.").Required().String()
	// githubScanToken := githubScan.Flag("token", "GitHub token.").String()

	gitlabScan := cli.Command("gitlab", "Find credentials in GitLab repositories.")
	// gitlabScanTarget := gitlabScan.Arg("target", "GitLab target. Can be a repository, user or organization.").Required().String()
	// gitlabScanToken := gitlabScan.Flag("token", "GitLab token.").String()

	// bitbucketScan := cli.Command("bitbucket", "Find credentials in Bitbucket repositories.")
	// bitbucketScanTarget := bitbucketScan.Arg("target", "Bitbucket target. Can be a repository, user or organization.").Required().String()
	// bitbucketScanToken := bitbucketScan.Flag("token", "Bitbucket token.").String()

	// filesystemScan := cli.Command("filesystem", "Find credentials in filesystem.")
	// filesystemScanPath := filesystemScan.Arg("path", "Path to scan.").Required().String()
	// filesystemScanRecursive := filesystemScan.Flag("recursive", "Scan recursively.").Short('r').Bool()
	// filesystemScanIncludePaths := filesystemScan.Flag("include_paths", "Path to file with newline separated regexes for files to include in scan.").Short('i').String()
	// filesystemScanExcludePaths := filesystemScan.Flag("exclude_paths", "Path to file with newline separated regexes for files to exclude in scan.").Short('x').String()

	cmd := kingpin.MustParse(cli.Parse(os.Args[1:]))

	if *jsonOut {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	ctx := context.TODO()
	e := engine.Start(ctx,
		engine.WithConcurrency(*concurrency),
		engine.WithDecoders(decoders.DefaultDecoders()...),
		engine.WithDetectors(!*noVerification, engine.DefaultDetectors()...),
	)

	filter, err := common.FilterFromFiles(*gitScanIncludePaths, *gitScanExcludePaths)
	if err != nil {
		logrus.WithError(err)
	}

	switch cmd {
	case gitScan.FullCommand():
		repoPath, remote, err := git.PrepareRepo(*gitScanURI)
		if err != nil || repoPath == "" {
			logrus.WithError(err).Fatal("error preparing git repo for scanning")
		}
		if remote {
			defer os.RemoveAll(repoPath)
		}
		err = e.ScanGit(ctx, repoPath, *gitScanBranch, "HEAD", filter)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to scan git.")
		}
	case githubScan.FullCommand():
		log.Fatal("github not implemented")
	case gitlabScan.FullCommand():
		log.Fatal("gitlab not implemented")
	}

	// deal with the results from e.ResultsChan()
	for r := range e.ResultsChan() {
		if *jsonOut {
			// todo - add parity to trufflehog's existing output for git
			// source
			out, err := json.Marshal(r)
			if err != nil {
				logrus.WithError(err).Fatal("could not marshal result")
			}
			fmt.Println(string(out))
		} else {
			fmt.Printf("%+v\n", r)
		}
	}
	logrus.Infof("scanned %d chunks", e.ChunksScanned())
}
