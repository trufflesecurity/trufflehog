package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// gitResult builds a verified result from a git-family source, which has file/line metadata.
func gitResult(verified bool) *detectors.ResultWithMetadata {
	return &detectors.ResultWithMetadata{
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Git{
				Git: &source_metadatapb.Git{File: "config/prod.yaml", Line: 42},
			},
		},
		SourceType:          sourcespb.SourceType_SOURCE_TYPE_GIT,
		SourceName:          "my-repo",
		DetectorDescription: "AWS credentials",
		Result: detectors.Result{
			DetectorType: detector_typepb.DetectorType_AWS,
			Raw:          []byte("secret"),
			Verified:     verified,
		},
	}
}

// elasticsearchResult builds a result from a source with no file/line concept.
func elasticsearchResult() *detectors.ResultWithMetadata {
	return &detectors.ResultWithMetadata{
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Elasticsearch{
				Elasticsearch: &source_metadatapb.Elasticsearch{Index: "logs", DocumentId: "123"},
			},
		},
		SourceType:          sourcespb.SourceType_SOURCE_TYPE_ELASTICSEARCH,
		SourceName:          "my-cluster",
		DetectorDescription: "Slack token",
		Result: detectors.Result{
			DetectorType: detector_typepb.DetectorType_Slack,
			Raw:          []byte("secret"),
			Verified:     false,
		},
	}
}

func TestSarifPrinter_PrintAndFlush(t *testing.T) {
	p := &SarifPrinter{}
	ctx := context.Background()

	require.NoError(t, p.Print(ctx, gitResult(true)))
	require.NoError(t, p.Print(ctx, elasticsearchResult()))

	var buf bytes.Buffer
	require.NoError(t, p.Flush(&buf))

	var doc sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	assert.Equal(t, sarifVersion, doc.Version)
	assert.Equal(t, sarifSchemaURI, doc.Schema)
	require.Len(t, doc.Runs, 1)

	run := doc.Runs[0]
	assert.Equal(t, "trufflehog", run.Tool.Driver.Name)
	require.Len(t, run.Tool.Driver.Rules, 2, "one rule per distinct detector type")
	require.Len(t, run.Results, 2)

	// Verified git result: file/line populated, level "error".
	gitFinding := run.Results[0]
	assert.Equal(t, "AWS", gitFinding.RuleID)
	assert.Equal(t, sarifLevelError, gitFinding.Level)
	assert.Equal(t, "config/prod.yaml", gitFinding.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	require.NotNil(t, gitFinding.Locations[0].PhysicalLocation.Region)
	assert.EqualValues(t, 42, gitFinding.Locations[0].PhysicalLocation.Region.StartLine)
	assert.NotEmpty(t, gitFinding.PartialFingerprints["trufflehogFingerprint/v1"])

	// Unverified elasticsearch result: no file/line, falls back to a source URI, level "warning".
	esFinding := run.Results[1]
	assert.Equal(t, "Slack", esFinding.RuleID)
	assert.Equal(t, sarifLevelWarning, esFinding.Level)
	assert.Equal(t, "source_type_elasticsearch://my-cluster", esFinding.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Nil(t, esFinding.Locations[0].PhysicalLocation.Region)
}

func TestSarifPrinter_FlushWithNoResults(t *testing.T) {
	p := &SarifPrinter{}

	var buf bytes.Buffer
	require.NoError(t, p.Flush(&buf))

	var doc sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.Len(t, doc.Runs, 1)
	assert.NotNil(t, doc.Runs[0].Results, "results must be an empty array, not null, per the SARIF spec")
	assert.Empty(t, doc.Runs[0].Results)
}

func TestSarifFingerprint_StableAndDistinct(t *testing.T) {
	a := sarifFingerprint("AWS", "config/prod.yaml", 42, []byte("secret1"))
	b := sarifFingerprint("AWS", "config/prod.yaml", 42, []byte("secret1"))
	assert.Equal(t, a, b, "fingerprint must be stable across calls with identical inputs")

	c := sarifFingerprint("AWS", "config/prod.yaml", 43, []byte("secret1"))
	assert.NotEqual(t, a, c, "fingerprint must change when the finding location changes")

	// Same rule/location but no file/line (e.g. Postman, Elasticsearch) must not collapse
	// distinct secrets into the same fingerprint.
	d := sarifFingerprint("Slack", "elasticsearch://my-cluster", 0, []byte("secret1"))
	e := sarifFingerprint("Slack", "elasticsearch://my-cluster", 0, []byte("secret2"))
	assert.NotEqual(t, d, e, "fingerprint must differ for distinct secrets sharing a fileless location")
}

// TestSarifPrinter_FingerprintStableAcrossVerificationChange guards against regressing to a
// fingerprint that includes verification status: if a secret's status flips between scans (API
// error, rate limit, credential rotation), the fingerprint must stay the same so GitHub code
// scanning tracks it as the same finding rather than closing/reopening an alert.
func TestSarifPrinter_FingerprintStableAcrossVerificationChange(t *testing.T) {
	ctx := context.Background()

	unverified := &SarifPrinter{}
	require.NoError(t, unverified.Print(ctx, gitResult(false)))

	verified := &SarifPrinter{}
	require.NoError(t, verified.Print(ctx, gitResult(true)))

	assert.Equal(t,
		unverified.results[0].PartialFingerprints["trufflehogFingerprint/v1"],
		verified.results[0].PartialFingerprints["trufflehogFingerprint/v1"],
	)
}

func TestSarifArtifactURI(t *testing.T) {
	assert.Equal(t, "config/prod.yaml", sarifArtifactURI("config/prod.yaml", "SOURCE_TYPE_GIT", "my-repo"))
	assert.Equal(t, "source_type_elasticsearch://my-cluster", sarifArtifactURI("", "SOURCE_TYPE_ELASTICSEARCH", "my-cluster"))
}
