package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

// SARIF (Static Analysis Results Interchange Format) 2.1.0 identifiers.
// See https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
const (
	sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion   = "2.1.0"

	// sarifLevelError/sarifLevelWarning map to SARIF's result.level. Verified secrets are
	// confirmed live credentials and are reported as errors; unverified secrets matched a
	// detector pattern but could not be confirmed, and are reported as warnings so that tools
	// consuming SARIF (e.g. GitHub code scanning) can triage them separately.
	sarifLevelError   = "error"
	sarifLevelWarning = "warning"
)

// SarifPrinter is a printer that accumulates results and, once the scan completes, emits them
// as a single SARIF 2.1.0 log. Unlike the other Printer implementations, SARIF results cannot be
// streamed one-per-line: the spec requires one JSON document containing every run and result, so
// Print only buffers results and Flush performs the actual marshal/write.
//
// TODO: results are held in memory for the full scan and Flush marshals them in one pass, so peak
// memory grows with result count (roughly 2x at Flush, for the struct plus its marshaled JSON).
// Fine for typical scan sizes; if scans with very large result counts start OOMing, switch to
// writing results to the underlying writer incrementally as they're produced in Print.
type SarifPrinter struct {
	mu      sync.Mutex
	results []sarifResult
	rules   map[string]*sarifRule // keyed by detector type name, de-duplicated across results
}

// Print buffers a single result for inclusion in the SARIF document written by Flush.
func (p *SarifPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	meta, err := structToMap(r.SourceMetadata.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	file, line := extractFileAndLine(meta)
	ruleID := r.DetectorType.String()

	level := sarifLevelWarning
	if r.Verified {
		level = sarifLevelError
	}

	verifiedStatus := "unverified"
	if r.Verified {
		verifiedStatus = "verified"
	}

	location := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{
				URI: sarifArtifactURI(file, r.SourceType.String(), r.SourceName),
			},
		},
	}
	// SARIF's region is optional; only sources whose metadata carries a line number (git,
	// filesystem, S3, etc.) can populate it. Sources like Postman or Elasticsearch have no
	// concept of a line, so region is omitted rather than reported as a misleading zero.
	if line > 0 {
		location.PhysicalLocation.Region = &sarifRegion{StartLine: line}
	}

	result := sarifResult{
		RuleID:  ruleID,
		Level:   level,
		Message: sarifMessage{Text: fmt.Sprintf("Found %s result for detector %s.", verifiedStatus, ruleID)},
		Locations: []sarifLocation{
			location,
		},
		// PartialFingerprints lets GitHub code scanning (and other SARIF consumers) match the
		// same finding across scans, so it can track a secret as "new" or "fixed" instead of
		// reporting it fresh on every run.
		PartialFingerprints: map[string]string{
			"trufflehogFingerprint/v1": sarifFingerprint(ruleID, location.PhysicalLocation.ArtifactLocation.URI, line, r.Raw),
		},
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rules == nil {
		p.rules = make(map[string]*sarifRule)
	}
	if _, ok := p.rules[ruleID]; !ok {
		p.rules[ruleID] = &sarifRule{
			ID:               ruleID,
			Name:             ruleID,
			ShortDescription: sarifMessage{Text: r.DetectorDescription},
		}
	}
	p.results = append(p.results, result)

	return nil
}

// Flush marshals every result buffered by Print into a single SARIF 2.1.0 log and writes it to
// w. It must be called exactly once, after all Print calls have completed (i.e. once the scan
// has finished), since SARIF is a single JSON document rather than a streamable format.
func (p *SarifPrinter) Flush(w io.Writer) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	rules := make([]*sarifRule, 0, len(p.rules))
	for _, rule := range p.rules {
		rules = append(rules, rule)
	}
	// Sort for deterministic output; map iteration order is randomized in Go.
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	results := p.results
	if results == nil {
		// Emit an empty array rather than JSON null when nothing was found.
		results = []sarifResult{}
	}

	doc := sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "trufflehog",
						InformationURI: "https://github.com/trufflesecurity/trufflehog",
						Version:        version.BuildVersion,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal SARIF output: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("could not write SARIF output: %w", err)
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// extractFileAndLine pulls the "file" and "line" fields out of a result's source metadata, if
// present. Most source metadata types (git, filesystem, S3, docker, ...) carry these fields, but
// not all do, so both return values may be zero.
func extractFileAndLine(meta map[string]map[string]any) (file string, line int64) {
	for _, data := range meta {
		for k, v := range data {
			switch k {
			case "file":
				if f, ok := v.(string); ok {
					file = f
				}
			case "line":
				if l, ok := v.(float64); ok {
					line = int64(l)
				}
			}
		}
	}
	return file, line
}

// sarifArtifactURI returns the best-effort identifier for where a secret was found. It prefers
// the file path from source metadata; when a source has no file concept (e.g. Postman,
// Elasticsearch) it falls back to a "<sourcetype>://<sourcename>" URI so the location field is
// never empty, which the SARIF spec requires.
func sarifArtifactURI(file, sourceType, sourceName string) string {
	if file != "" {
		return file
	}
	return fmt.Sprintf("%s://%s", strings.ToLower(sourceType), sourceName)
}

// sarifFingerprint derives a stable identifier for a finding so SARIF consumers can recognize
// the same secret across repeated scans (e.g. to mark it "fixed" once it no longer appears).
// Verification status is deliberately excluded: it's already carried in the result's "level"
// field, and including it here would change the fingerprint (and reset alert history) whenever
// a secret's verification flips between runs. The raw secret value is included so that sources
// with no file/line concept (Postman, Elasticsearch, ...) don't collapse every finding of the
// same detector type into one fingerprint.
func sarifFingerprint(ruleID, uri string, line int64, raw []byte) string {
	key := fmt.Sprintf("%s:%s:%d:%x", ruleID, uri, line, sha256.Sum256(raw))
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// The following types implement a minimal subset of the SARIF 2.1.0 object model needed to
// describe trufflehog's results. Only fields trufflehog actually populates are included; the
// full spec has many optional fields that aren't relevant here.
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
	Name           string       `json:"name"`
	InformationURI string       `json:"informationUri"`
	Version        string       `json:"version"`
	Rules          []*sarifRule `json:"rules"`
}

// sarifRule describes a detector as a SARIF "rule". One rule is emitted per distinct detector
// type that produced at least one result.
type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int64 `json:"startLine"`
}
