package squareapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`[\w\-]*sq0i[a-z]{2}-[0-9A-Za-z\-_]{22,43}`)
	secPat = regexp.MustCompile(`[\w\-]*sq0c[a-z]{2}-[0-9A-Za-z\-_]{40,50}`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sq0i")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAll(data, -1)
	secMatches := secPat.FindAll(data, -1)

	for _, match := range matches {
		for _, secMatch := range secMatches {

			if detectors.IsKnownFalsePositive(bytes.ToLower(secMatch), detectors.DefaultFalsePositives, true) {
				continue
			}

			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_SquareApp,
				Raw:          match,
			}

			if verify {
				baseURL := "https://connect.squareupsandbox.com/oauth2/revoke"

				client := common.SaneHttpClient()
				reqData, err := json.Marshal(map[string][]byte{
					"client_id":    match,
					"access_token": []byte("fakeTruffleHogAccessTokenForVerification"),
				})
				if err != nil {
					return nil, err
				}

				req, err := http.NewRequestWithContext(ctx, "POST", baseURL, bytes.NewReader(reqData))
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Client %s", string(secMatch)))
				req.Header.Add("Content-Type", "application/json")

				res, err := client.Do(req)
				if err == nil {
					res.Body.Close()
					if res.StatusCode == http.StatusNotFound {
						s.Verified = true
					}
				}
			}

			if !s.Verified && detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s)
		}
	}
	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SquareApp
}
