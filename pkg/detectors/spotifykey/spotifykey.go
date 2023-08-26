package spotifykey

import (
	"bytes"
	"context"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"key", "secret"}) + `\b([A-Za-z0-9]{32})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"id"}) + `\b([A-Za-z0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("spotify")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, common.SaneHttpClient())

	matches := secretPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			idresMatch := bytes.TrimSpace(idMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SpotifyKey,
				Raw:          resMatch,
			}

			if verify {
				config := &clientcredentials.Config{
					ClientID:     string(idresMatch),
					ClientSecret: string(resMatch),
					TokenURL:     "https://accounts.spotify.com/api/token",
				}
				token, err := config.Token(ctx)
				if err == nil {
					if token.Type() == "Bearer" {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}
			results = append(results, s1)
		}

	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SpotifyKey
}
