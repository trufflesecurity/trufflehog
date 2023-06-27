package telegrambottoken

import (
	"context"
	//	"fmt"
	"net/http"
	"regexp"
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

	// https://core.telegram.org/bots#6-botfather
	// thanks https://stackoverflow.com/questions/61868770/tegram-bot-api-token-format
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"telegram"}) + `\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"telegram"}
}

// FromData will find and optionally verify TelegramBotToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		key := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_TelegramBotToken,
			Raw:          []byte(key),
		}

		if verify {
			// https://core.telegram.org/bots/api#getme
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.telegram.org/bot"+key+"/getMe", nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else {
					if detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TelegramBotToken
}
