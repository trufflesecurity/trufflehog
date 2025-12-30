package datadogapikey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDataDogApiKey_Pattern_WithValidAPIKey(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := `
			dd_api_secret: "FKNwdbyfYTmGUm5DK3yHEuK-BBQf0fVG"
			dd_app: "iHxNanzZ8vjrmbjXK7NJLrwpGw2czdSh90PKH6VL"
			base_url1: "https://api.us5.datadoghq.com"
			base_url2: "https://api.app.ddog-gov.com"
	`
	apiKey := "FKNwdbyfYTmGUm5DK3yHEuK-BBQf0fVG"
	wantedResult := []detectors.Result{
		{
			DetectorType: detectorspb.DetectorType_DatadogApikey,
			Raw:          []byte(apiKey),
			RawV2:        []byte(apiKey),
			ExtraData: map[string]string{
				"Type": "APIKeyOnly",
			},
		},
	}
	matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(input))
	if len(matchedDetectors) == 0 {
		t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), input)
		return
	}
	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Errorf("error = %v", err)
		return
	}

	if diff := cmp.Diff(wantedResult, results, cmpopts.IgnoreFields(detectors.Result{}, "verificationError", "primarySecret")); diff != "" {
		t.Errorf("%s diff: (-want +got)\n%s", "TestDataDogApiKey_Pattern_WithValidAPIKeyOnly", diff)
	}
}

func TestDataDogApiKey_NoSecrets(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := `
			base_url1: "https://api.us5.datadoghq.com"
			base_url2: "https://api.app.ddog-gov.com"
	`
	matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(input))
	if len(matchedDetectors) == 0 {
		t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), input)
		return
	}
	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Errorf("error = %v", err)
		return
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, received %d", len(results))
	}
}

func TestDataDogApiKey_InvalidSecrets(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := `
			dd_api_secret: "@FKNwdbyfYTmGUm5DK3yHEuK"
			dd_app: "iHxNanzZ8vjrmbjXK7NJLrwpGw2czdSh90PKH6VL"
			base_url1: "https://api.us5.datadoghq.com"
			base_url2: "https://api.app.ddog-gov.com"
	`
	matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(input))
	if len(matchedDetectors) == 0 {
		t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), input)
		return
	}
	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Errorf("error = %v", err)
		return
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, received %d", len(results))
	}
}
