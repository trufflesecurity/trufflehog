package datadogtoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDataDogToken_Pattern_WithValidAPIandAppKey(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := `
			dd_api_secret: "FKNwdbyfYTmGUm5DK3yHEuK-BBQf0fVG"
			dd_app: "iHxNanzZ8vjrmbjXK7NJLrwpGw2czdSh90PKH6VL"
			base_url1: "https://api.us5.datadoghq.com"
			base_url2: "https://api.app.ddog-gov.com"
	`
	want := []string{"iHxNanzZ8vjrmbjXK7NJLrwpGw2czdSh90PKH6VLFKNwdbyfYTmGUm5DK3yHEuK-BBQf0fVG"}
	wantedResultType := "Application+APIKey"
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
	if len(results) != len(want) {
		if len(results) == 0 {
			t.Errorf("did not receive result")
		} else {
			t.Errorf("expected %d results, only received %d", len(want), len(results))
		}
		return
	}

	actual := make(map[string]struct{}, len(results))
	for _, r := range results {
		if len(r.RawV2) > 0 {
			actual[string(r.RawV2)] = struct{}{}
		} else {
			actual[string(r.Raw)] = struct{}{}
		}
		if r.ExtraData["Type"] != wantedResultType {
			t.Errorf("expected result type %s, got %s", wantedResultType, r.ExtraData["Type"])
		}
	}
	expected := make(map[string]struct{}, len(want))
	for _, v := range want {
		expected[v] = struct{}{}
	}

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("%s diff: (-want +got)\n%s", "TestDataDogToken_Pattern_WithValidAPIKeyOnly", diff)
	}
}

func TestDataDogToken_Pattern_WithAPIKeyOnly(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := `
			dd_api_secret: "FKNwdbyfYTmGUm5DK3yHEuK-BBQf0fVG"
			base_url: "https://api.us5.datadoghq.com"
			response_code: 200
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

func TestDataDogToken_NoSecrets(t *testing.T) {
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

func TestDataDogToken_InvalidSecrets(t *testing.T) {
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
