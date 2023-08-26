package githubapp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	appPat = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `\b([0-9]{6})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `(-----BEGIN RSA PRIVATE KEY-----\s[A-Za-z0-9+\/\s]*\s-----END RSA PRIVATE KEY-----)`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("github")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)
	appMatches := appPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		for _, appMatch := range appMatches {
			if len(appMatch) != 2 {
				continue
			}

			appResMatch := bytes.TrimSpace(appMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GitHubApp,
				Raw:          resMatch,
			}

			if verify {
				signKey, err := jwt.ParseRSAPrivateKeyFromPEM(resMatch)
				if err != nil {
					continue
				}

				iat := time.Now().Add(-60 * time.Second)
				exp := time.Now().Add(9 * 60 * time.Second)
				iss := string(appResMatch)

				token := jwt.New(jwt.SigningMethodRS256)
				claims := token.Claims.(jwt.MapClaims)
				claims["iat"] = iat.Unix()
				claims["exp"] = exp.Unix()
				claims["iss"] = iss

				tokenString, err := token.SignedString(signKey)
				if err != nil {
					continue
				}

				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/app", nil)
				if err != nil {
					continue
				}

				req.Header.Add("Accept", "application/vnd.github.v3+json")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenString))

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GitHubApp
}
