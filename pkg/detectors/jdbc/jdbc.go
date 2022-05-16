package jdbc

import (
	"context"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`(?i)jdbc:[\w]{3,10}:\/\/\w[\s\S]{0,512}?password[=: \"']+(?P<pass>[^<{($]*?)[ \s'\"]+`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"jdbc"}
}

// FromData will find and optionally verify Jdbc secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if match[1] == "" {
			continue
		}
		token := match[0]
		password := match[1]

		//TODO if username and password are the same, username will also be redacted... I think this is  probably correct.
		redact := strings.TrimSpace(strings.Replace(token, password, strings.Repeat("*", len(password)), -1))

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_JDBC,
			Raw:          []byte(token),
			Redacted:     redact,
		}

		//if verify {
		//	// TODO: can this be verified? Possibly. Could triage verification to other DBMS strings
		//	s.Verified = false
		//	client := common.SaneHttpClient()
		//	req, err := http.NewRequestWithContext(ctx, "GET", "https://jdbcci.com/api/v2/me", nil)
		//	if err != nil {
		//		continue
		//	}
		//	req.Header.Add("Accept", "application/json;")
		//	req.Header.Add("Jdbc-Token", token)
		//	res, err := client.Do(req)
		//	if err == nil {
		//		if res.StatusCode >= 200 && res.StatusCode < 300 {
		//			s.Verified = true
		//		}
		//	}
		//}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s)
	}

	return
}
