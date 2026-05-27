package influxdb

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		`influx(?:db)?[_-]?(?:api[_-]?)?token`,
		`datasource[_-][a-z0-9_-]{0,32}[_-]token`,
	}) + `\b([A-Za-z0-9_-]{40,}={0,2})(?:[^A-Za-z0-9_\-=]|$)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"influx", "influxdb", "datasource"}
}

// FromData will find InfluxDB tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[strings.TrimSpace(matches[1])] = struct{}{}
	}

	for token := range uniqueTokens {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_InfluxDB,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"token": token},
		})
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_InfluxDB
}

func (s Scanner) Description() string {
	return "InfluxDB is a time-series database. InfluxDB tokens can be used to access buckets and manage data depending on their permissions."
}
