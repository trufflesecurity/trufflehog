package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// SARIFPrinter accumulates scan results and formats them as a SARIF 2.1.0 JSON document.
type SARIFPrinter struct {
	mu      sync.Mutex
	results []*detectors.ResultWithMetadata
	Writer  io.Writer // Optional; if nil, defaults to os.Stdout
}

// Print thread-safely stores a scan result to be printed at the end of the run.
func (p *SARIFPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results = append(p.results, r)
	return nil
}

// Flush compiles all accumulated results into a SARIF JSON output and prints it.
func (p *SARIFPrinter) Flush(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Deduplicate findings using a content-based hash (similar to GitHubActionsPrinter)
	var dedupe = make(map[string]struct{})
	rulesMap := make(map[string]sarifRule)
	var sarifResults []sarifResult

	for _, r := range p.results {
		var startLine int = 1
		var filename string = "unknown"

		if r.SourceMetadata != nil && r.SourceMetadata.Data != nil {
			meta, err := structToMap(r.SourceMetadata.Data)
			if err == nil {
				for _, data := range meta {
					for k, v := range data {
						if k == "line" {
							if line, ok := v.(float64); ok {
								startLine = int(line)
							}
						}
						if k == "file" {
							if name, ok := v.(string); ok {
								filename = name
							}
						}
					}
				}
			}
		}

		verifiedStatus := "unverified"
		if r.Verified {
			verifiedStatus = "verified"
		}

		key := fmt.Sprintf("%s:%s:%s:%s:%d", r.DecoderType.String(), r.DetectorType.String(), verifiedStatus, filename, startLine)
		h := sha256.New()
		h.Write([]byte(key))
		hashKey := hex.EncodeToString(h.Sum(nil))

		if _, ok := dedupe[hashKey]; ok {
			continue
		}
		dedupe[hashKey] = struct{}{}

		detectorID := r.DetectorType.String()
		if detectorID == "" || r.DetectorType == 0 {
			detectorID = r.DetectorName
		}
		if detectorID == "" {
			detectorID = "unknown_detector"
		}

		if _, ok := rulesMap[detectorID]; !ok {
			desc := r.DetectorDescription
			if desc == "" {
				desc = fmt.Sprintf("Credential detected by %s detector", detectorID)
			}
			rulesMap[detectorID] = sarifRule{
				ID:   detectorID,
				Name: detectorID,
				ShortDescription: sarifMessageString{
					Text: desc,
				},
				HelpURI: "https://github.com/trufflesecurity/trufflehog",
			}
		}

		level := "warning"
		verifiedText := "unverified"
		if r.Verified {
			level = "error"
			verifiedText = "verified"
		}

		name := ""
		if nameValue, ok := r.ExtraData["name"]; ok {
			name = fmt.Sprintf(" (%s)", nameValue)
		}

		messageText := fmt.Sprintf("Found %s %s%s result \U0001F437\U0001F511", verifiedText, detectorID, name)

		sarifResults = append(sarifResults, sarifResult{
			RuleID:  detectorID,
			Level:   level,
			Message: sarifMessage{Text: messageText},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: filename,
						},
						Region: sarifRegion{
							StartLine: startLine,
							Snippet: &sarifSnippet{
								Text: r.Redacted,
							},
						},
					},
				},
			},
		})
	}

	// Sort rules deterministically by ID
	var rules []sarifRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	// Wrap in top-level SARIF structure
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "TruffleHog",
						InformationURI: "https://github.com/trufflesecurity/trufflehog",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal SARIF output: %w", err)
	}

	w := p.Writer
	if w == nil {
		w = os.Stdout
	}
	_, err = fmt.Fprintln(w, string(out))
	return err
}

// SARIF Go structs mapping to the SARIF 2.1.0 JSON Schema

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifMessageString `json:"shortDescription"`
	HelpURI          string             `json:"helpUri"`
}

type sarifMessageString struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level,omitempty"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int           `json:"startLine"`
	Snippet   *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}
