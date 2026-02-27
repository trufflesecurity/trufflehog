package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// GitHubActionsStepSummaryPrinter is a printer that outputs to the GitHub Actions step summary.
// It produces a Markdown table with links to the specific locations where secrets were found.
type GitHubActionsStepSummaryPrinter struct {
	mu              sync.Mutex
	file            *os.File
	headerWritten   bool
	dedupeCache     map[string]struct{}
	resultCount     int
	verifiedCount   int
	unverifiedCount int
}

type stepSummaryResult struct {
	DetectorType string
	Verified     bool
	Filename     string
	Commit       string
	Link         string
	Line         int64
	Column       int64
}

func (p *GitHubActionsStepSummaryPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Initialize on first call
	if p.dedupeCache == nil {
		p.dedupeCache = make(map[string]struct{})
	}

	// Open the step summary file if not already open
	if p.file == nil {
		summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
		if summaryPath == "" {
			// Fall back to stdout if not in GitHub Actions
			p.file = os.Stdout
		} else {
			var err error
			p.file, err = os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("could not open step summary file: %w", err)
			}
		}
	}

	out := stepSummaryResult{
		DetectorType: r.Result.DetectorType.String(),
		Verified:     r.Result.Verified,
	}

	// Extract metadata from the source
	if r.SourceMetadata != nil {
		// Try to get GitHub-specific metadata first
		if github := r.SourceMetadata.GetGithub(); github != nil {
			out.Filename = github.GetFile()
			out.Commit = github.GetCommit()
			out.Link = github.GetLink()
			out.Line = github.GetLine()
		} else if gitlab := r.SourceMetadata.GetGitlab(); gitlab != nil {
			out.Filename = gitlab.GetFile()
			out.Commit = gitlab.GetCommit()
			out.Link = gitlab.GetLink()
			out.Line = gitlab.GetLine()
		} else if git := r.SourceMetadata.GetGit(); git != nil {
			out.Filename = git.GetFile()
			out.Commit = git.GetCommit()
			out.Line = git.GetLine()
			// Git source doesn't have a link, construct one if possible
			if git.GetRepository() != "" {
				out.Link = giturl.GenerateLink(git.GetRepository(), git.GetCommit(), git.GetFile(), git.GetLine())
			}
		} else if bitbucket := r.SourceMetadata.GetBitbucket(); bitbucket != nil {
			out.Filename = bitbucket.GetFile()
			out.Commit = bitbucket.GetCommit()
			out.Link = bitbucket.GetLink()
			out.Line = bitbucket.GetLine()
		} else if filesystem := r.SourceMetadata.GetFilesystem(); filesystem != nil {
			out.Filename = filesystem.GetFile()
			out.Link = filesystem.GetLink()
			out.Line = filesystem.GetLine()
		} else {
			// Fall back to generic metadata extraction
			meta, err := structToMap(r.SourceMetadata.Data)
			if err == nil {
				for _, data := range meta {
					if line, ok := data["line"].(float64); ok {
						out.Line = int64(line)
					}
					if filename, ok := data["file"].(string); ok {
						out.Filename = filename
					}
					if commit, ok := data["commit"].(string); ok {
						out.Commit = commit
					}
					if link, ok := data["link"].(string); ok {
						out.Link = link
					}
				}
			}
		}
	}

	// Create deduplication key
	verifiedStatus := "unverified"
	if out.Verified {
		verifiedStatus = "verified"
	}

	key := fmt.Sprintf("%s:%s:%s:%s:%d", out.DetectorType, verifiedStatus, out.Filename, out.Commit, out.Line)
	h := sha256.New()
	h.Write([]byte(key))
	hashKey := hex.EncodeToString(h.Sum(nil))

	if _, ok := p.dedupeCache[hashKey]; ok {
		return nil
	}
	p.dedupeCache[hashKey] = struct{}{}

	// Write header on first result
	if !p.headerWritten {
		fmt.Fprintln(p.file, "## 🐷🔑 TruffleHog Secrets Scan Results")
		fmt.Fprintln(p.file, "")
		fmt.Fprintln(p.file, "| Secret Type | Status | File | Line |")
		fmt.Fprintln(p.file, "|-------------|--------|------|------|")
		p.headerWritten = true
	}

	// Format verified status with emoji
	statusEmoji := "🔲 Unverified"
	if out.Verified {
		statusEmoji = "✅ Verified"
		p.verifiedCount++
	} else {
		p.unverifiedCount++
	}
	p.resultCount++

	// Format the file location with optional link
	fileLocation := formatFileLocation(out.Filename, out.Commit, out.Link)

	// Add name to detector type if available
	detectorDisplay := out.DetectorType
	if nameValue, ok := r.Result.ExtraData["name"]; ok {
		detectorDisplay = fmt.Sprintf("%s (%s)", out.DetectorType, nameValue)
	}

	// Include encoding info if not plain
	if r.DecoderType != detectorspb.DecoderType_PLAIN {
		detectorDisplay = fmt.Sprintf("%s [%s]", detectorDisplay, r.DecoderType.String())
	}

	// Write the table row
	fmt.Fprintf(p.file, "| %s | %s | %s | %d |\n",
		escapeMarkdown(detectorDisplay),
		statusEmoji,
		fileLocation,
		out.Line)

	return nil
}

// Finish writes the summary footer with counts
func (p *GitHubActionsStepSummaryPrinter) Finish() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.file == nil {
		return nil
	}

	if p.resultCount > 0 {
		fmt.Fprintln(p.file, "")
		fmt.Fprintf(p.file, "### Summary\n")
		fmt.Fprintf(p.file, "- **Total secrets found:** %d\n", p.resultCount)
		fmt.Fprintf(p.file, "- **Verified:** %d\n", p.verifiedCount)
		fmt.Fprintf(p.file, "- **Unverified:** %d\n", p.unverifiedCount)
	} else if p.headerWritten {
		fmt.Fprintln(p.file, "")
		fmt.Fprintln(p.file, "✅ No secrets found!")
	}

	// Close the file if it's not stdout
	if p.file != os.Stdout {
		return p.file.Close()
	}
	return nil
}

// formatFileLocation creates a markdown link for the file if a link is available
func formatFileLocation(filename, commit, link string) string {
	if filename == "" {
		filename = "unknown"
	}

	displayName := filename
	if commit != "" {
		// Show short commit hash
		shortCommit := commit
		if len(commit) > 7 {
			shortCommit = commit[:7]
		}
		displayName = fmt.Sprintf("%s @ %s", filename, shortCommit)
	}

	if link != "" {
		return fmt.Sprintf("[%s](%s)", escapeMarkdown(displayName), link)
	}
	return escapeMarkdown(displayName)
}

// escapeMarkdown escapes special markdown characters in text
func escapeMarkdown(text string) string {
	// Escape pipe characters as they break table formatting
	text = strings.ReplaceAll(text, "|", "\\|")
	return text
}
