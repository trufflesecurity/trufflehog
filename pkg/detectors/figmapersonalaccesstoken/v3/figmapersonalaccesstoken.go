package figmapersonalaccesstoken

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	figma "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/figmapersonalaccesstoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 3 }

var (
	defaultClient = common.SaneHttpClient()
	// The figp_ token charset includes '=' and '-', which are not word characters,
	// so a \b word boundary can't be used to anchor the end of the match. Instead we
	// require the next character to be outside the token charset (or end of input).
	keyPat = regexp.MustCompile(`(figp_[a-zA-Z0-9_=-]{40,54})(?:[^a-zA-Z0-9_=-]|\z)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"figp_"}
}

func (s Scanner) Description() string {
	return "Figma is a collaborative interface design tool. Figma Personal Access Tokens can be used to access and manipulate design files and other resources on behalf of a user."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify FigmaPersonalAccessToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(resMatch),
			ExtraData: map[string]string{
				"version": fmt.Sprint(s.Version()),
			},
			SecretParts: map[string]string{"token": resMatch},
		}

		if verify {
			isVerified, verificationErr := figma.VerifyMatch(ctx, s.getClient(), resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_FigmaPersonalAccessToken
}
