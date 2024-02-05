package shodankey

import (
	"context"
	"encoding/json"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"shodan"}) + `\b([a-zA-Z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"shodan"}
}

// FromData will find and optionally verify ShodanKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	// log.Println(dataStr)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ShodanKey,
			Raw:          []byte(resMatch),
		}

		if verify {
			s1.Verified = verifyToken(ctx, client, resMatch)
			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}
		}
		results = append(results, s1)
	}

	return results, nil
}

type shodanInfoRes struct {
	ScanCredits int `json:"scan_credits"`
	UsageLimits struct {
		ScanCredits  int `json:"scan_credits"`
		QueryCredits int `json:"query_credits"`
		MonitoredIps int `json:"monitored_ips"`
	} `json:"usage_limits"`
	Plan         string `json:"plan"`
	HTTPS        bool   `json:"https"`
	Unlocked     bool   `json:"unlocked"`
	QueryCredits int    `json:"query_credits"`
	MonitoredIps int    `json:"monitored_ips"`
	UnlockedLeft int    `json:"unlocked_left"`
	Telnet       bool   `json:"telnet"`
}

func verifyToken(ctx context.Context, client *http.Client, token string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.shodan.io/api-info?key="+token, nil)
	if err != nil {
		return false
	}

	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return false
	}

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false
	}

	var info shodanInfoRes
	return json.Unmarshal(bytes, &info) == nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ShodanKey
}
