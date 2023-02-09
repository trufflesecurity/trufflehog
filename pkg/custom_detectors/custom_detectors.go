package custom_detectors

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// The maximum number of matches from one chunk. This const is used when
// permutating each regex match to protect the scanner from doing too much work
// for poorly defined regexps.
const maxTotalMatches = 100

// customRegexWebhook is a CustomRegex with webhook validation that is
// guaranteed to be valid (assuming the data is not changed after
// initialization).
type customRegexWebhook struct {
	*custom_detectorspb.CustomRegex
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*customRegexWebhook)(nil)

// NewWebhookCustomRegex initializes and validates a customRegexWebhook. An
// unexported type is intentionally returned here to ensure the values have
// been validated.
func NewWebhookCustomRegex(pb *custom_detectorspb.CustomRegex) (*customRegexWebhook, error) {
	// TODO: Return all validation errors.
	if err := ValidateKeywords(pb.Keywords); err != nil {
		return nil, err
	}
	if err := ValidateRegex(pb.Regex); err != nil {
		return nil, err
	}

	for _, verify := range pb.Verify {
		if err := ValidateVerifyEndpoint(verify.Endpoint, verify.Unsafe); err != nil {
			return nil, err
		}
		if err := ValidateVerifyHeaders(verify.Headers); err != nil {
			return nil, err
		}
	}

	// TODO: Copy only necessary data out of pb.
	return &customRegexWebhook{pb}, nil
}

var httpClient = common.SaneHttpClient()

func (c *customRegexWebhook) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	regexMatches := make(map[string][][]string, len(c.GetRegex()))

	// Find all submatches for each regex.
	for name, regex := range c.GetRegex() {
		regex, err := regexp.Compile(regex)
		if err != nil {
			// This will only happen if the regex is invalid.
			return nil, err
		}
		regexMatches[name] = regex.FindAllStringSubmatch(dataStr, -1)
	}

	// Permutate each individual match.
	// {
	//    "foo": [["match1"]]
	//    "bar": [["match2"], ["match3"]]
	// }
	// becomes
	// [
	//    {"foo": ["match1"], "bar": ["match2"]},
	//    {"foo": ["match1"], "bar": ["match3"]},
	// ]
	matches := permutateMatches(regexMatches)

	// Create result object and test for verification.
	for _, match := range matches {
		if common.IsDone(ctx) {
			// TODO: Log we're possibly leaving out results.
			return results, nil
		}
		var raw string
		for _, values := range match {
			// values[0] contains the entire regex match.
			raw += values[0]
		}
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_CustomRegex,
			Raw:          []byte(raw),
		}

		if !verify {
			results = append(results, result)
			continue
		}
		// Verify via webhook.
		jsonBody, err := json.Marshal(map[string]map[string][]string{
			c.GetName(): match,
		})
		if err != nil {
			continue
		}
		// Try each config until we successfully verify.
		for _, verifyConfig := range c.GetVerify() {
			if common.IsDone(ctx) {
				// TODO: Log we're possibly leaving out results.
				return results, nil
			}
			req, err := http.NewRequestWithContext(ctx, "POST", verifyConfig.GetEndpoint(), bytes.NewReader(jsonBody))
			if err != nil {
				continue
			}
			for _, header := range verifyConfig.GetHeaders() {
				key, value, found := strings.Cut(header, ":")
				if !found {
					// Should be unreachable due to validation.
					continue
				}
				req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))
			}
			res, err := httpClient.Do(req)
			if err != nil {
				continue
			}
			// TODO: Read response body.
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				result.Verified = true
				break
			}
		}
		results = append(results, result)
	}

	return results, nil
}

func (c *customRegexWebhook) Keywords() []string {
	return c.GetKeywords()
}

// productIndices produces a permutation of indices for each length. Example:
// productIndices(3, 2) -> [[0 0] [1 0] [2 0] [0 1] [1 1] [2 1]]. It returns
// a slice of length no larger than maxTotalMatches.
func productIndices(lengths ...int) [][]int {
	count := 1
	for _, l := range lengths {
		count *= l
	}
	if count == 0 {
		return nil
	}
	if count > maxTotalMatches {
		count = maxTotalMatches
	}

	results := make([][]int, count)
	for i := 0; i < count; i++ {
		j := 1
		result := make([]int, 0, len(lengths))
		for _, l := range lengths {
			result = append(result, (i/j)%l)
			j *= l
		}
		results[i] = result
	}
	return results
}

// permutateMatches converts the list of all regex matches into all possible
// permutations selecting one from each named entry in the map. For example:
// {"foo": [matchA, matchB], "bar": [matchC]} becomes
//
// [{"foo": matchA, "bar": matchC}, {"foo": matchB, "bar": matchC}]
func permutateMatches(regexMatches map[string][][]string) []map[string][]string {
	// Get a consistent order for names and their matching lengths.
	// The lengths are used in calculating the permutation so order matters.
	names := make([]string, 0, len(regexMatches))
	lengths := make([]int, 0, len(regexMatches))
	for key, value := range regexMatches {
		names = append(names, key)
		lengths = append(lengths, len(value))
	}

	// Permutate all the indices for each match. For example, if "foo" has
	// [matchA, matchB] and "bar" has [matchC], we will get indices [0 0] [1 0].
	permutationIndices := productIndices(lengths...)

	// Build {"foo": matchA, "bar": matchC} and {"foo": matchB, "bar": matchC}
	// from the indices.
	var matches []map[string][]string
	for _, permutation := range permutationIndices {
		candidate := make(map[string][]string, len(permutationIndices))
		for i, name := range names {
			candidate[name] = regexMatches[name][permutation[i]]
		}
		matches = append(matches, candidate)
	}

	return matches
}

func (c *customRegexWebhook) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CustomRegex
}
