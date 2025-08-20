package grafanaapikey

import (
	"context"
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,2})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
// Grafana uses "eyJrIjoi" as a prefix for api keys, see for example.
// https://github.com/grafana/pyroscope-dotnet/blob/0c17634653af09befa7bc07b2e1c420b5dc8578c/tracer/src/Datadog.Trace/Iast/Analyzers/HardcodedSecretsAnalyzer.cs#L173
func (s Scanner) Keywords() []string {
	return []string{"grafanaapikey", "eyJrIjoi"}
}

// FromData will find and optionally verify Grafanaapikey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		res := detectors.Result{
			DetectorType: detectorspb.DetectorType_GrafanaAPIKey,
			Raw:          []byte(match),
		}

		if verify {
			res.SetVerificationError(fmt.Errorf("no grafana instance detected to verify against"), match)
		}

		results = append(results, res)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GrafanaAPIKey
}

func (s Scanner) Description() string {
	return "Grafana API keys are used to authenticate and interact with Grafana's API. These credentials can be used to access and modify Grafana resources and settings."
}
