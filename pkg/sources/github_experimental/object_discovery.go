package github_experimental

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-github/v67/github"
	"github.com/k0kubun/go-ansi"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

// Assumption: sleeping for 60 seconds is enough to reset the secondary rate limit
// see https://docs.github.com/en/graphql/overview/rate-limits-and-node-limits-for-the-graphql-api#secondary-rate-limits
const secondaryRateLimitSleep = 60

// Assumption: on average, a fork contributes 0.1% additional commits
const forkCommitMultiplier = 0.001

// Threshold for estimated Short SHA-1 hash collisions (default to 1...so basically none)
// as calculated using the Birthday Paradox
// Adjust this to a higher value if you're willing to accept more collisions (and shorter runtime).
var collisionThreshold float64

// Starting character length (4 is the minimum required by git)
const startingCharLen = 4

// Max character length (6 is the default maximum)
// 6 chars == 16M possibilities --> which will take 18k-55k queries.
// that's really the max that's tolerable since it will take a long time to run.
// If you increase this to accommodate a MASSIVE repository, it will take a long time to run.
const maxCharLen = 6

// Starting GraphQL query chunk size.
// Max that worked was 900.
// 350 is a safe starting point.
const maxChunkSize = 900
const initialChunkSize = 350

// Max number of commits to fetch from the repository in one command
// ex: git fetch origin <commit1> <commit2> ... <commit1000>
const gitFetchMax = 1000

// Constants for commit types
const (
	invalidCommit     = "invalid"
	validHiddenCommit = "valid_hidden"
)

type backoff struct {
	value              float64
	decreasePercentage float64
	increasePercentage float64
	successThreshold   int
	successCount       int
}

func newBackoff(initialValue, decreasePercentage, increasePercentage float64, successThreshold int) *backoff {
	return &backoff{
		value:              initialValue,
		decreasePercentage: decreasePercentage,
		increasePercentage: increasePercentage,
		successThreshold:   successThreshold,
	}
}

func (b *backoff) errorOccurred() float64 {
	b.value -= b.value * (b.decreasePercentage / 100)
	b.successCount = 0 // Reset success count on error
	if b.value < 100 {
		b.value = 100
	}
	return b.value
}

func (b *backoff) successOccurred() float64 {
	b.successCount++
	if b.successCount >= b.successThreshold {
		b.value += b.value * (b.increasePercentage / 100)
		b.successCount = 0 // Reset success count after increasing the value
	}
	if b.value > maxChunkSize {
		b.value = maxChunkSize
	}
	return b.value
}

func (b *backoff) getValue() int {
	return int(b.value)
}

// Github token
var ghToken = ""

func getForksCount(owner, repoName string) (int, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: ghToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	repo, _, err := client.Repositories.Get(ctx, owner, repoName)
	if err != nil {
		return 0, err
	}

	return repo.GetForksCount(), nil
}

func getGitHubUser() (string, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: ghToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	ghUser, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return "", err
	}
	return ghUser.GetLogin(), nil
}

// runGitCommand runs a git command
func runGitCommand(args []string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func getExistingHashes(path string) ([]string, error) {
	var hashes []string
	gitArgs := []string{
		"-C",
		path,
		"--work-tree",
		path,
		"cat-file",
		"--batch-check",
		"--batch-all-objects",
	}
	outputBytes, err := runGitCommand(gitArgs)
	if err != nil {
		return hashes, err
	}

	output := string(outputBytes)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if len(line) > 0 {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				hashes = append(hashes, parts[0])
			}
		}
	}
	return hashes, nil
}

// calculateUsedKeySet Estimates the total used key set -
// meaning how many used hashes are in the repository.
func calculateUsedKeySet(commitCount, forksCount int) int {
	// Calculate total known key set
	commits := float64(commitCount)
	forks := float64(forksCount)
	knownKeySet := (commits + (commits * forkCommitMultiplier * forks))

	return int(knownKeySet)
}

// Estimate the number of collisions using the Birthday Paradox
func estimateCollisions(keySpace, knownKeySet int) float64 {
	keySpaceF := float64(keySpace)
	knownKeySetF := float64(knownKeySet)
	return (knownKeySetF * (knownKeySetF - 1)) / (2 * keySpaceF)
}

func getShortShaLen(knownKeySet int) int {
	// Calculate the length of the short SHA-1 hash
	// This is the minimum length required to avoid collisions
	// in the estimated known key set
	shortShaLen := startingCharLen
	keySpace := 1 << (shortShaLen * 4)
	collisions := estimateCollisions(keySpace, knownKeySet)
	for collisions > collisionThreshold {
		if shortShaLen >= maxCharLen {
			break
		}
		shortShaLen++
		keySpace = 1 << (shortShaLen * 4)
		collisions = estimateCollisions(keySpace, knownKeySet)
	}

	return shortShaLen
}

// Generate all possible min commit hashes
func generateShortSHAStrings(charLen int) []string {
	hexDigits := "0123456789abcdef"
	var hexStrings []string
	var generateCombinations func(prefix string, length int)

	generateCombinations = func(prefix string, length int) {
		if length == 0 {
			hexStrings = append(hexStrings, prefix)
			return
		}
		for _, digit := range hexDigits {
			generateCombinations(prefix+string(digit), length-1)
		}
	}

	generateCombinations("", charLen)
	return hexStrings
}

// Write commits to disk
func writeCommitsToDisk(commits []string, commitsType, folder string) error {
	filename := fmt.Sprintf("%s/%s.txt", folder, commitsType)

	// Open file in append mode, create if it doesn't exist
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, commit := range commits {
		if _, err := file.WriteString(commit + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// Read commits from disk
func readCommitsFromDisk(commitsType, folder string) ([]string, error) {
	filename := fmt.Sprintf("%s/%s.txt", folder, commitsType)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var commits []string
	for _, line := range lines {
		if line != "" {
			commits = append(commits, strings.TrimSpace(line))
		}
	}
	return removeNewlineAndUnique(commits), nil
}

// Remove newlines from commits and make them unique
func removeNewlineAndUnique(commits []string) []string {
	commitMap := make(map[string]struct{})
	for _, commit := range commits {
		cleanCommit := strings.TrimSpace(commit)
		commitMap[cleanCommit] = struct{}{}
	}
	var uniqueCommits []string
	for commit := range commitMap {
		uniqueCommits = append(uniqueCommits, commit)
	}
	return uniqueCommits
}

// Remove commits that are already in the existing_commits list
func removeByShortSHA(existingCommits, newCommits []string) []string {
	existingSet := make(map[string]struct{})
	for _, commit := range existingCommits {
		existingSet[commit] = struct{}{}
	}
	var filteredCommits []string
	for _, commit := range newCommits {
		if _, exists := existingSet[commit]; !exists {
			filteredCommits = append(filteredCommits, commit)
		}
	}
	return filteredCommits
}

// Remove commits that are already in the existing_commits list (by char_len)
func removeBySHA(existingCommits, newCommits []string, charLen int) []string {
	existingSet := make(map[string]struct{})
	for _, commit := range existingCommits {
		shortSHA := commit
		if len(commit) > charLen {
			shortSHA = commit[:charLen]
		}
		existingSet[shortSHA] = struct{}{}
	}
	var filteredCommits []string
	for _, commit := range newCommits {
		shortSHA := commit
		if len(commit) > charLen {
			shortSHA = commit[:charLen]
		}
		if _, exists := existingSet[shortSHA]; !exists {
			filteredCommits = append(filteredCommits, commit)
		}
	}
	return filteredCommits
}

func processCommits(ctx context.Context, needsProcessing []string, owner, repo, path string) {
	repoCtx := context.WithValue(ctx, "repo", repo)

	startingSize := float64(len(needsProcessing))
	queryChunkSize := newBackoff(initialChunkSize, 10, 10, 1)

	// Initialize the progress bar for commit processing
	bar := progressbar.NewOptions(int(startingSize),
		progressbar.OptionSetDescription("[green]Processing commits[reset]"),
		progressbar.OptionSetWriter(ansi.NewAnsiStderr()),
		progressbar.OptionEnableColorCodes(true),
	)

	for len(needsProcessing) > 0 {
		if len(needsProcessing) < queryChunkSize.getValue() {
			queryChunkSize.value = float64(len(needsProcessing))
		}
		chunkSize := queryChunkSize.getValue()
		chunk := needsProcessing[:chunkSize]
		needsProcessing = needsProcessing[chunkSize:]

		commitData, err := checkHashes(owner, repo, chunk)
		if err != nil {
			repoCtx.Logger().V(2).Info("Temporary error occurred in guessing commits", "error", err)
			needsProcessing = append(needsProcessing, chunk...)
			queryChunkSize.errorOccurred()
			if strings.Contains(err.Error(), "You have exceeded a secondary rate limit") {
				repoCtx.Logger().V(2).Info("Reached secondary GitHub Rate Limit. Sleeping for 60 seconds.")
				time.Sleep(secondaryRateLimitSleep * time.Second)
			}
			continue
		}

		percentCompleted := (1 - (float64(len(needsProcessing)) / startingSize)) * 100

		repoCtx.Logger().V(2).Info("Progress", "percent_completed", percentCompleted, "needs_processing", len(needsProcessing))

		queryChunkSize.successOccurred()
		err = writeCommitsToDisk(commitData[validHiddenCommit], validHiddenCommit, path)
		if err != nil {
			repoCtx.Logger().V(2).Info("Failed to write valid hidden commits to disk", "error", err)
		}
		err = writeCommitsToDisk(commitData[invalidCommit], invalidCommit, path)
		if err != nil {
			repoCtx.Logger().V(2).Info("Failed to write invalid commits to disk", "error", err)
		}

		// Update the progress bar
		_ = bar.Add(chunkSize)
	}

	// Finish the progress bar
	_ = bar.Finish()
}

type commitData struct {
	OID string `json:"oid"`
}

type responseData struct {
	Data struct {
		Repository map[string]commitData `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Message string `json:"message"`
}

func checkHashes(owner, repo string, hashes []string) (map[string][]string, error) {
	testCases := ""
	for _, h := range hashes {
		testCase := fmt.Sprintf(`
        commit%s: object(expression: "%s") {
          ... on Commit {
            oid
          }
        }
      `, h, h)
		testCases += testCase
	}

	query := fmt.Sprintf(`
      query {
        repository(owner: "%s", name: "%s") {
          %s
        }
      }
    `, owner, repo, testCases)

	headers := map[string]string{
		"Authorization":         "Bearer " + ghToken,
		"Content-Type":          "application/json",
		"Github-Verified-Fetch": "true",
		"X-Requested-With":      "XMLHttpRequest",
		"Accept-Language":       "en-US,en;q=0.9",
		"Priority":              "u=1, i",
	}

	requestBody, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("python request error: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var data responseData
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(data.Errors) > 0 {
		return nil, fmt.Errorf("%s (GitHub Request Error)", strings.Split(data.Errors[0].Message, ".")[0])
	}
	if data.Message != "" {
		return nil, fmt.Errorf("%s (GitHub Request Error)", strings.Split(data.Message, ".")[0])
	}

	commits := data.Data.Repository

	valid_cfor := []string{}
	invalid := []string{}

	for commit, value := range commits {
		commit = strings.Replace(commit, "commit", "", 1)
		if value.OID == "{}" || value.OID == "" {
			invalid = append(invalid, commit)
		} else {
			valid_cfor = append(valid_cfor, value.OID)
		}
	}

	res := map[string][]string{
		validHiddenCommit: valid_cfor,
		invalidCommit:     invalid,
	}

	return res, nil
}

// createBatches divides a slice into batches of a specified size
func createBatches(items []string, batchSize int) <-chan []string {
	out := make(chan []string)
	go func() {
		defer close(out)
		itemsCopy := append([]string(nil), items...)
		for len(itemsCopy) > 0 {
			end := batchSize
			if len(itemsCopy) < batchSize {
				end = len(itemsCopy)
			}
			batch := itemsCopy[:end]
			itemsCopy = itemsCopy[end:]
			out <- batch
		}
	}()
	return out
}

// downloadPatches fetches and checks out cfor commits
func downloadPatches(valid_cfor []string, path string) error {
	// Download all patches
	for batch := range createBatches(valid_cfor, gitFetchMax) {
		gitArgs := []string{
			"-C",
			path,
			"--work-tree",
			path,
			"fetch",
			"--quiet",
			"origin",
		}
		gitArgs = append(gitArgs, batch...)
		_, err := runGitCommand(gitArgs)
		if err != nil {
			return err
		}
	}

	// Checkout each commit
	// Note: path and worktree are needed or else git will do something funny with the actual cwd
	for _, commit := range valid_cfor {
		branchName := fmt.Sprintf("_%s", commit)
		gitArgs := []string{
			"-C",
			path,
			"--work-tree",
			path,
			"checkout",
			"--quiet",
			"-b",
			branchName,
			commit,
		}
		_, err := runGitCommand(gitArgs)
		if err != nil {
			return fmt.Errorf("failed to checkout commit %s: %v", commit, err)
		}
	}

	return nil
}

// scanHiddenData scans hidden data (and non-hidden data) for secrets in a GitHub repository
func (s *Source) EnumerateAndScanAllObjects(ctx context.Context, chunksChan chan *sources.Chunk) error {
	// assign github token to global variable
	ghToken = s.conn.GetToken()

	// set collision threshold to user input
	collisionThreshold = float64(s.conn.CollisionThreshold)

	// parse the repo URL
	repoURL, urlParts, err := getRepoURLParts(s.conn.Repository)
	if err != nil {
		return fmt.Errorf("failed to get repo URL parts: %w", err)
	}

	// read in the owner and repo name
	owner := urlParts[1]
	repoName := urlParts[2]

	// get repo metadata and store in cacheRepoInfo
	repoCtx := context.WithValue(ctx, "repo", owner+"/"+repoName)
	ghRepo, _, err := s.apiClient.Repositories.Get(repoCtx, owner, repoName)
	if err != nil {
		return fmt.Errorf("failed to fetch repository: %w", err)
	}
	s.cacheRepoInfo(ghRepo)

	// Create a folder housing the repo and commit data
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}

	folderPath := userHomeDir + "/.trufflehog/" + owner + "/" + repoName
	err = os.MkdirAll(folderPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create .trufflehog folder in user's home directory: %w", err)
	}

	// Get GitHub User tied to token
	ghUser, err := getGitHubUser()
	if err != nil {
		return fmt.Errorf("failed to get GitHub user details: %w", err)
	}

	// get the number of forks
	forksCount, err := getForksCount(owner, repoName)
	if err != nil {
		return fmt.Errorf("failed to get forks count: %w", err)
	}

	// download the repo
	path, repo, err := git.CloneRepoUsingToken(ctx, ghToken, repoURL, ghUser, true)
	if err != nil {
		return fmt.Errorf("failed to clone the repository: %w", err)
	}

	defer os.RemoveAll(path)

	// count total valid hashes
	validHashes, err := getExistingHashes(path)
	if err != nil {
		return fmt.Errorf("failed to enumerate existing commit object hashes: %w", err)
	}

	// Calculate estimated used key set
	estimatedUsedKeySet := calculateUsedKeySet(len(validHashes), forksCount)

	// Calculate Short SHA-1 Length for Unambiguous Commit Identifiers
	shortShaLen := getShortShaLen(estimatedUsedKeySet)

	// Log stats
	repoCtx.Logger().V(2).Info("Estimated used keys", "count", estimatedUsedKeySet)
	repoCtx.Logger().V(2).Info("Target Short SHA-1 length", "length", shortShaLen)
	repoCtx.Logger().V(2).Info("Estimated collisions", "count", estimateCollisions(1<<(shortShaLen*4), estimatedUsedKeySet))

	// Read in existing commits (if any)
	validHiddenCommits, err := readCommitsFromDisk(validHiddenCommit, folderPath)
	if err != nil {
		return fmt.Errorf("failed to read valid hidden commits from disk: %w", err)
	}

	invalidCommits, err := readCommitsFromDisk(invalidCommit, folderPath)
	if err != nil {
		return fmt.Errorf("failed to read invalid commits from disk: %w", err)
	}

	// Generate all possible commit hashes using the short SHA-1 length
	possibleCommits := generateShortSHAStrings(shortShaLen)

	// Remove commits that are already used by the repo or previously calculated (on restart)
	possibleCommits = removeBySHA(validHashes, possibleCommits, shortShaLen)
	possibleCommits = removeBySHA(validHiddenCommits, possibleCommits, shortShaLen)
	possibleCommits = removeByShortSHA(invalidCommits, possibleCommits)

	// Guess all possible commit hashes
	processCommits(ctx, possibleCommits, owner, repoName, folderPath)

	// Read in the new commits
	validHiddenCommits, err = readCommitsFromDisk(validHiddenCommit, folderPath)
	if err != nil {
		return fmt.Errorf("failed to read valid hidden commits from disk: %w", err)
	}

	// Download commit hashes and checkout into branches (only way scanner will pick them up)
	err = downloadPatches(validHiddenCommits, path)
	if err != nil {
		return fmt.Errorf("failed to download patches: %w", err)
	}

	// Scan git for secrets
	repoCtx.Logger().V(2).Info("scanning for secrets in repo", "repo_url", repoURL)
	start := time.Now()
	err = s.git.ScanRepo(ctx, repo, path, s.scanOptions, sources.ChanReporter{Ch: chunksChan})
	if err != nil {
		return fmt.Errorf("failed to scan repo: %w", err)
	}
	duration := time.Since(start)
	repoCtx.Logger().V(2).Info("scanned 1 repo for hidden data", "duration_seconds", duration)

	// Remove the folder if user requests
	if s.conn.DeleteCachedData {
		err = os.RemoveAll(folderPath)
		if err != nil {
			return fmt.Errorf("failed to delete cached data: %w", err)
		}
	}

	return nil
}
