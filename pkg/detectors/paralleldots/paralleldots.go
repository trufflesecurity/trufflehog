package paralleldots

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"paralleldots"}) + `\b([0-9A-Za-z]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"paralleldots"}
}

// FromData will find and optionally verify Paralleldots secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_ParallelDots,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	fw, err := writer.CreateFormField("api_key")
	if err != nil {
		return false, err
	}
	_, err = io.Copy(fw, strings.NewReader(resMatch))
	if err != nil {
		return false, err
	}
	fw, err = writer.CreateFormField("text")
	if err != nil {
		return false, err
	}
	_, err = io.Copy(fw, strings.NewReader("sample text"))
	if err != nil {
		return false, err
	}
	_ = writer.Close()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://apis.paralleldots.com/v4/intent", bytes.NewReader(payload.Bytes()))
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	body := string(bodyBytes)
	if (res.StatusCode >= 200 && res.StatusCode < 300) && strings.Contains(body, "intent") {
		return true, nil
	}

	return false, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ParallelDots
}

func (s Scanner) Description() string {
	return "ParallelDots is an AI service offering various APIs for text analysis. API keys can be used to access these services."
}
