package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

func TestSARIFPrinter(t *testing.T) {
	ctx := context.Background()

	res1 := &detectors.ResultWithMetadata{
		Result: detectors.Result{
			DetectorType: detector_typepb.DetectorType_URI,
			Verified:     true,
			Redacted:     "secret-redacted-1",
		},
		DetectorDescription: "URI description",
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Git{
				Git: &source_metadatapb.Git{
					Commit: "abcdef",
					File:   "main.go",
					Line:   10,
				},
			},
		},
	}

	// Duplicate of res1 but different commit (should be deduplicated based on file/line/type)
	res1Dup := &detectors.ResultWithMetadata{
		Result: detectors.Result{
			DetectorType: detector_typepb.DetectorType_URI,
			Verified:     true,
			Redacted:     "secret-redacted-1-dup",
		},
		DetectorDescription: "URI description",
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Git{
				Git: &source_metadatapb.Git{
					Commit: "ghijk",
					File:   "main.go",
					Line:   10,
				},
			},
		},
	}

	res2 := &detectors.ResultWithMetadata{
		Result: detectors.Result{
			DetectorType: detector_typepb.DetectorType_AWS,
			Verified:     false,
			Redacted:     "secret-redacted-2",
		},
		DetectorDescription: "AWS description",
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Git{
				Git: &source_metadatapb.Git{
					Commit: "lmnop",
					File:   "config.json",
					Line:   25,
				},
			},
		},
	}

	var buf bytes.Buffer
	printer := &SARIFPrinter{
		Writer: &buf,
	}

	if err := printer.Print(ctx, res1); err != nil {
		t.Fatalf("Print failed: %v", err)
	}
	if err := printer.Print(ctx, res1Dup); err != nil {
		t.Fatalf("Print failed: %v", err)
	}
	if err := printer.Print(ctx, res2); err != nil {
		t.Fatalf("Print failed: %v", err)
	}

	if err := printer.Flush(ctx); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	output := buf.String()

	// Parse output back into SarifLog structure to validate correctness
	var log sarifLog
	if err := json.Unmarshal([]byte(output), &log); err != nil {
		t.Fatalf("Failed to parse output as JSON: %v. Output was:\n%s", err, output)
	}

	if log.Version != "2.1.0" {
		t.Errorf("Expected version 2.1.0, got %s", log.Version)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "TruffleHog" {
		t.Errorf("Expected tool name TruffleHog, got %s", run.Tool.Driver.Name)
	}

	// We expect 2 unique rules since URI and AWS are distinct, and the duplicate is removed
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Check sorted order of rules
	if run.Tool.Driver.Rules[0].ID != "AWS" || run.Tool.Driver.Rules[1].ID != "URI" {
		t.Errorf("Rules are not sorted correctly: [0] = %s, [1] = %s", run.Tool.Driver.Rules[0].ID, run.Tool.Driver.Rules[1].ID)
	}

	// We expect 2 results due to deduplication
	if len(run.Results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(run.Results))
	}

	// The first result should be URI (verified) or AWS (unverified) depending on ordering, let's look up both
	var awsResult, uriResult *sarifResult
	for i := range run.Results {
		res := &run.Results[i]
		if res.RuleID == "AWS" {
			awsResult = res
		} else if res.RuleID == "URI" {
			uriResult = res
		}
	}

	if uriResult == nil {
		t.Errorf("URI result not found in output")
	} else {
		if uriResult.Level != "error" {
			t.Errorf("Expected verified URI level to be 'error', got '%s'", uriResult.Level)
		}
		if !strings.Contains(uriResult.Message.Text, "verified URI") {
			t.Errorf("Unexpected message text: %s", uriResult.Message.Text)
		}
		if len(uriResult.Locations) != 1 {
			t.Fatalf("Expected 1 location for URI, got %d", len(uriResult.Locations))
		}
		loc := uriResult.Locations[0]
		if loc.PhysicalLocation.ArtifactLocation.URI != "main.go" {
			t.Errorf("Expected URI filename to be 'main.go', got '%s'", loc.PhysicalLocation.ArtifactLocation.URI)
		}
		if loc.PhysicalLocation.Region.StartLine != 10 {
			t.Errorf("Expected URI line to be 10, got %d", loc.PhysicalLocation.Region.StartLine)
		}
		if loc.PhysicalLocation.Region.Snippet == nil || loc.PhysicalLocation.Region.Snippet.Text != "secret-redacted-1" {
			t.Errorf("Expected snippet to contain 'secret-redacted-1'")
		}
	}

	if awsResult == nil {
		t.Errorf("AWS result not found in output")
	} else {
		if awsResult.Level != "warning" {
			t.Errorf("Expected unverified AWS level to be 'warning', got '%s'", awsResult.Level)
		}
		if !strings.Contains(awsResult.Message.Text, "unverified AWS") {
			t.Errorf("Unexpected message text: %s", awsResult.Message.Text)
		}
		loc := awsResult.Locations[0]
		if loc.PhysicalLocation.ArtifactLocation.URI != "config.json" {
			t.Errorf("Expected AWS filename to be 'config.json', got '%s'", loc.PhysicalLocation.ArtifactLocation.URI)
		}
		if loc.PhysicalLocation.Region.StartLine != 25 {
			t.Errorf("Expected AWS line to be 25, got %d", loc.PhysicalLocation.Region.StartLine)
		}
		if loc.PhysicalLocation.Region.Snippet == nil || loc.PhysicalLocation.Region.Snippet.Text != "secret-redacted-2" {
			t.Errorf("Expected snippet to contain 'secret-redacted-2'")
		}
	}
}
