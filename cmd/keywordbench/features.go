package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// New detectors ship gated behind a feature flag and are filtered out of
// defaults.DefaultDetectors() until it is set. The CLI turns them all on in
// main.go, so the benchmark must too -- otherwise the newest detector, the one
// most worth benchmarking, is silently absent from both the scan and the
// percentile population.
//
// checkFeatureDrift compares this list against main.go and warns when they
// diverge, so adding a detector without updating this file is caught rather than
// quietly narrowing the population.
var detectorFeatures = map[string]*atomic.Bool{
	"HTMLDecoderEnabled":                       &feature.HTMLDecoderEnabled,
	"PineconeDetectorEnabled":                  &feature.PineconeDetectorEnabled,
	"CloudinaryDetectorEnabled":                &feature.CloudinaryDetectorEnabled,
	"GitLabOAuthDetectorEnabled":               &feature.GitLabOAuthDetectorEnabled,
	"FigmaV3DetectorEnabled":                   &feature.FigmaV3DetectorEnabled,
	"SonarCloudV2DetectorEnabled":              &feature.SonarCloudV2DetectorEnabled,
	"EnigmaDetectorEnabled":                    &feature.EnigmaDetectorEnabled,
	"DatadogApiKeyDetectorEnabled":             &feature.DatadogApiKeyDetectorEnabled,
	"TlyDetectorEnabled":                       &feature.TlyDetectorEnabled,
	"WitDetectorEnabled":                       &feature.WitDetectorEnabled,
	"RevDetectorEnabled":                       &feature.RevDetectorEnabled,
	"UserDetectorEnabled":                      &feature.UserDetectorEnabled,
	"BraintrustDetectorEnabled":                &feature.BraintrustDetectorEnabled,
	"PgAnalyzeReadKeyDetectorEnabled":          &feature.PgAnalyzeReadKeyDetectorEnabled,
	"RedHatPyxisDetectorEnabled":               &feature.RedHatPyxisDetectorEnabled,
	"OctopusDeployDetectorEnabled":             &feature.OctopusDeployDetectorEnabled,
	"OpenRouterDetectorEnabled":                &feature.OpenRouterDetectorEnabled,
	"NewRelicInsightsInsertKeyDetectorEnabled": &feature.NewRelicInsightsInsertKeyDetectorEnabled,
	"DuffelTokenDetectorEnabled":               &feature.DuffelTokenDetectorEnabled,
	"ShippoDetectorEnabled":                    &feature.ShippoDetectorEnabled,
	"IPInfoDetectorEnabled":                    &feature.IPInfoDetectorEnabled,
	"LobDetectorEnabled":                       &feature.LobDetectorEnabled,
	"HashiCorpVaultBatchTokenDetectorEnabled":  &feature.HashiCorpVaultBatchTokenDetectorEnabled,
	"HashiCorpVaultTokenDetectorEnabled":       &feature.HashiCorpVaultTokenDetectorEnabled,
	"CloudflareApiTokenV2DetectorEnabled":      &feature.CloudflareApiTokenV2DetectorEnabled,
	"CloudflareGlobalApiKeyV2DetectorEnabled":  &feature.CloudflareGlobalApiKeyV2DetectorEnabled,
	"DuoDetectorEnabled":                       &feature.DuoDetectorEnabled,
	"NewRelicLicenseKeyDetectorEnabled":        &feature.NewRelicLicenseKeyDetectorEnabled,
	"NewRelicBrowserKeyDetectorEnabled":        &feature.NewRelicBrowserKeyDetectorEnabled,
	"NewRelicUserKeyDetectorEnabled":           &feature.NewRelicUserKeyDetectorEnabled,
	"NewRelicInsightsQueryKeyDetectorEnabled":  &feature.NewRelicInsightsQueryKeyDetectorEnabled,
	"NewRelicMobileAppTokenDetectorEnabled":    &feature.NewRelicMobileAppTokenDetectorEnabled,
	"MSTeamsWebhookV2DetectorEnabled":          &feature.MSTeamsWebhookV2DetectorEnabled,
	"SolarwindsDetectorEnabled":                &feature.SolarwindsDetectorEnabled,
}

func enableDetectorFeatures() {
	for _, flag := range detectorFeatures {
		flag.Store(true)
	}
}

var featureStorePat = regexp.MustCompile(`feature\.(\w+)\.Store\(true\)`)

// checkFeatureDrift is best-effort: it only reports when main.go is readable from
// the working directory, which is the normal `go run ./cmd/keywordbench` case.
func checkFeatureDrift(mainPath string) []string {
	src, err := os.ReadFile(mainPath)
	if err != nil {
		return nil
	}
	var missing []string
	for _, m := range featureStorePat.FindAllStringSubmatch(string(src), -1) {
		name := m[1]
		if _, ok := detectorFeatures[name]; ok {
			continue
		}
		// Only detector gating matters here; other flags change source or sink
		// behavior the benchmark never exercises.
		if strings.HasSuffix(name, "DetectorEnabled") {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%s is enabled in %s but not in cmd/keywordbench/features.go; "+
		"those detectors are missing from this run", missing, mainPath)}
}
