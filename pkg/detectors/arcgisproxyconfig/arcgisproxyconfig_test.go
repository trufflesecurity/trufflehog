package arcgisproxyconfig

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestScanner_FromData(t *testing.T) {
	t.Parallel()

	input := `<?xml version="1.0" encoding="utf-8"?>
<ProxyConfig allowedReferers="*" mustMatch="true" xmlns="proxy.xsd">
  <serverUrls>
    <serverUrl url="https://maps.example.invalid/arcgis/rest/services"
      username="gis-reader" password="Synthet1c!MapPass"
      tokenServiceUri="https://maps.example.invalid/sharing/generateToken"
      matchAll="true" />
    <serverUrl password='An0ther&amp;Synthetic' domain='EXAMPLE'
      matchAll='true' username='feature-reader'
      url='http://features.example.invalid/arcgis/rest/services'></serverUrl>
  </serverUrls>
</ProxyConfig>`

	scanner := Scanner{}
	results, err := scanner.FromData(context.Background(), false, []byte(input))
	require.NoError(t, err)

	want := []detectors.Result{
		{
			DetectorType: detector_typepb.DetectorType_ArcGISProxyConfig,
			Raw:          []byte("Synthet1c!MapPass"),
			RawV2:        []byte(`{"url":"https://maps.example.invalid/arcgis/rest/services","username":"gis-reader","password":"Synthet1c!MapPass"}`),
			Redacted:     "gis-reader@maps.example.invalid",
			SecretParts: map[string]string{
				"url":      "https://maps.example.invalid/arcgis/rest/services",
				"username": "gis-reader",
				"password": "Synthet1c!MapPass",
			},
		},
		{
			DetectorType: detector_typepb.DetectorType_ArcGISProxyConfig,
			Raw:          []byte("An0ther&Synthetic"),
			RawV2:        []byte(`{"url":"http://features.example.invalid/arcgis/rest/services","username":"feature-reader","password":"An0ther\u0026Synthetic","domain":"EXAMPLE"}`),
			Redacted:     `EXAMPLE\feature-reader@features.example.invalid`,
			SecretParts: map[string]string{
				"url":      "http://features.example.invalid/arcgis/rest/services",
				"username": "feature-reader",
				"password": "An0ther&Synthetic",
				"domain":   "EXAMPLE",
			},
		},
	}

	if diff := cmp.Diff(want, results, cmp.Comparer(equalPublicResult)); diff != "" {
		t.Fatalf("Scanner.FromData() mismatch (-want +got):\n%s", diff)
	}
	for _, result := range results {
		if result.Verified {
			t.Fatal("ArcGIS proxy-config credentials must remain unverified")
		}
		if result.VerificationError() != nil {
			t.Fatalf("unexpected verification error: %v", result.VerificationError())
		}
		if result.GetPrimarySecretValue() != string(result.Raw) {
			t.Fatalf("primary secret = %q, want %q", result.GetPrimarySecretValue(), result.Raw)
		}
	}
}

func TestScanner_NamespacePrefixAndDeduplication(t *testing.T) {
	t.Parallel()

	const tag = `<proxy:serverUrl xmlns:proxy="proxy.xsd" url="https://maps.example.invalid/arcgis" username="reader" password="Synthetic-Pass-42" />`
	input := tag + "\n" + tag

	results, err := (Scanner{}).FromData(context.Background(), false, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "Synthetic-Pass-42", string(results[0].Raw))
}

func TestScanner_RejectsNearMisses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "URL only",
			input: `<serverUrl url="https://services.example.invalid/arcgis" matchAll="true" />`,
		},
		{
			name:  "missing password",
			input: `<serverUrl url="https://services.example.invalid/arcgis" username="reader" />`,
		},
		{
			name:  "missing username",
			input: `<serverUrl url="https://services.example.invalid/arcgis" password="Synthetic-Pass-42" />`,
		},
		{
			name: "attributes split across elements",
			input: `<serverUrl url="https://one.example.invalid/arcgis" username="reader" />
				<serverUrl url="https://two.example.invalid/arcgis" password="Synthetic-Pass-42" />`,
		},
		{
			name:  "empty credential",
			input: `<serverUrl url="https://services.example.invalid/arcgis" username=" " password="" />`,
		},
		{
			name:  "environment variable",
			input: `<serverUrl url="https://services.example.invalid/arcgis" username="reader" password="${ARCGIS_PASSWORD}" />`,
		},
		{
			name:  "template expression",
			input: `<serverUrl url="https://services.example.invalid/arcgis" username="{{ ARCGIS_USER }}" password="Synthetic-Pass-42" />`,
		},
		{
			name:  "masked password",
			input: `<serverUrl url="https://services.example.invalid/arcgis" username="reader" password="XXXXXXXXXXXX" />`,
		},
		{
			name:  "redacted password",
			input: `<serverUrl url="https://services.example.invalid/arcgis" username="reader" password="[REDACTED]" />`,
		},
		{
			name:  "non HTTP URL",
			input: `<serverUrl url="file:///srv/arcgis" username="reader" password="Synthetic-Pass-42" />`,
		},
		{
			name:  "relative URL",
			input: `<serverUrl url="/arcgis/rest/services" username="reader" password="Synthetic-Pass-42" />`,
		},
		{
			name:  "duplicate required attribute",
			input: `<serverUrl url="https://one.example.invalid" url="https://two.example.invalid" username="reader" password="Synthetic-Pass-42" />`,
		},
		{
			name:  "namespaced credential attribute",
			input: `<serverUrl xmlns:secret="urn:example" url="https://services.example.invalid" username="reader" secret:password="Synthetic-Pass-42" />`,
		},
		{
			name:  "serverUrls container",
			input: `<serverUrls url="https://services.example.invalid" username="reader" password="Synthetic-Pass-42" />`,
		},
		{
			name:  "malformed unclosed quote",
			input: `<serverUrl url="https://services.example.invalid" username="reader" password="Synthetic-Pass-42 />`,
		},
		{
			name: "tag exceeds bounded credential span",
			input: `<serverUrl url="https://services.example.invalid" username="reader" password="Synthetic-Pass-42" metadata="` +
				strings.Repeat("a", maxServerURLTagSize) + `" />`,
		},
	}

	scanner := Scanner{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			results, err := scanner.FromData(context.Background(), true, []byte(test.input))
			require.NoError(t, err)
			require.Empty(t, results)
		})
	}
}

func TestScanner_VerificationRequestRemainsUnverified(t *testing.T) {
	t.Parallel()

	input := []byte(`<serverUrl url="https://maps.example.invalid/arcgis" username="reader" password="Synthetic-Pass-42" />`)
	scanner := Scanner{}

	unverified, err := scanner.FromData(context.Background(), false, input)
	require.NoError(t, err)
	verifyRequested, err := scanner.FromData(context.Background(), true, input)
	require.NoError(t, err)

	if diff := cmp.Diff(unverified, verifyRequested, cmp.Comparer(equalPublicResult)); diff != "" {
		t.Fatalf("verification request changed results (-verify=false +verify=true):\n%s", diff)
	}
	require.False(t, verifyRequested[0].Verified)
	require.NoError(t, verifyRequested[0].VerificationError())
}

func TestScanner_KeywordPrefilter(t *testing.T) {
	t.Parallel()

	scanner := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{scanner})

	matches := core.FindDetectorMatches([]byte(`<serverUrl url="https://maps.example.invalid" />`))
	require.Len(t, matches, 1)
	require.Equal(t, int64(maxServerURLTagSize), scanner.MaxCredentialSpan())
}

func equalPublicResult(left, right detectors.Result) bool {
	return left.DetectorType == right.DetectorType &&
		left.Verified == right.Verified &&
		string(left.Raw) == string(right.Raw) &&
		string(left.RawV2) == string(right.RawV2) &&
		left.Redacted == right.Redacted &&
		cmp.Equal(left.ExtraData, right.ExtraData) &&
		cmp.Equal(left.SecretParts, right.SecretParts)
}
