package railwayapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// graphQLResponse will handle the response from railway API
type graphQLResponse struct {
	Data   interface{}   `json:"data"`
	Errors []interface{} `json:"errors"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	apiToken = regexp.MustCompile(detectors.PrefixRegex([]string{"railway"}) +
		`\b([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"railway"}
}

func (s Scanner) Description() string {
	return "Railway is a deployment platform designed to streamline the software development life-cycle, starting with instant deployments and effortless scale, extending to CI/CD integrations and built-in observability."
}

// FromData will find and optionally verify SaladCloud API Key secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// uniqueMatches will hold unique match values and ensure we only process unique matches found in the data string
	var uniqueMatches = make(map[string]bool)

	for _, match := range apiToken.FindAllStringSubmatch(dataStr, -1) {
		if len(match) != 2 {
			continue
		}

		uniqueMatches[strings.TrimSpace(match[1])] = true
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_RailwayApp,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/railwayapp/",
			},
		}

		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyRailwayApp(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RailwayApp
}

/*
verifyRailwayApp verifies if the passed matched api key for railwayapp is active or not.
docs: https://docs.railway.app/reference/public-api
*/
func verifyRailwayApp(ctx context.Context, client *http.Client, match string) (bool, error) {
	jsonPayload, err := getJSONPayload()
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://backboard.railway.app/graphql/v2", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, err
	}

	// set the required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+match)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	/*
		GraphQL queries return response with 200 OK status code even for errors
		Sources:
		https://www.apollographql.com/docs/react/data/error-handling/#graphql-errors
		https://github.com/rmosolgo/graphql-ruby/issues/1130
		https://inigo.io/blog/graphql_error_handling
	*/
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("railway app verification failed with status code %d", resp.StatusCode)
	}

	// if rate limit is reached, return verification as false with no error
	if resp.Header.Get("x-ratelimit-remaining") == "0" {
		return false, nil
	}

	// read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// parse the response body into a structured format
	var graphqlResponse graphQLResponse
	if err = json.Unmarshal(body, &graphqlResponse); err != nil {
		return false, err
	}

	// if any errors exist in response, return verification as false
	if len(graphqlResponse.Errors) > 0 {
		return false, nil
	}

	return true, nil
}

// getJSONPayload return the graphQL query as a JSON
func getJSONPayload() ([]byte, error) {
	payload := map[string]string{
		"query": `query me {me {email}}`,
	}

	// convert the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling JSON: %w", err)
	}

	return jsonPayload, nil
}
