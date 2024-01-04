package custom_detectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"golang.org/x/sync/errgroup"
)

// The maximum number of matches from one chunk. This const is used when
// permutating each regex match to protect the scanner from doing too much work
// for poorly defined regexps.
const maxTotalMatches = 100

// CustomRegexWebhook is a CustomRegex with webhook validation that is
// guaranteed to be valid (assuming the data is not changed after
// initialization).
type CustomRegexWebhook struct {
	*custom_detectorspb.CustomRegex
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*CustomRegexWebhook)(nil)

// NewWebhookCustomRegex initializes and validates a CustomRegexWebhook. An
// unexported type is intentionally returned here to ensure the values have
// been validated.
func NewWebhookCustomRegex(pb *custom_detectorspb.CustomRegex) (*CustomRegexWebhook, error) {
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

		fmt.Println("verify headers", verify.Headers)
	}

	// TODO: Copy only necessary data out of pb.
	return &CustomRegexWebhook{pb}, nil
}

var httpClient = common.SaneHttpClient()
var validatorReplaceRegex = regexp.MustCompile(`(?i)\${([a-z0-9\-]{0,})}`)

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// This function generates all combinations of header values
func generateHeaderCombinations(setsOfHeaders map[string][]string) []map[string]string {
	var keys []string
	for k := range setsOfHeaders {
		keys = append(keys, k)
	}

	// Start with a single empty combination
	var combinations []map[string]string
	combinations = append(combinations, make(map[string]string))

	for _, key := range keys {
		newCombinations := []map[string]string{}
		for _, oldValueMap := range combinations {
			for _, value := range setsOfHeaders[key] {
				// Copy the old combination and add a new value for the current key
				newValueMap := make(map[string]string)
				for k, v := range oldValueMap {
					newValueMap[k] = v
				}
				newValueMap[key] = value
				newCombinations = append(newCombinations, newValueMap)
			}
		}
		combinations = newCombinations
	}
	return combinations
}

func (c *CustomRegexWebhook) doDirectVerify(ctx context.Context, matches []map[string][]string) (results []detectors.Result, err error) {
	verifier := c.GetVerify()[0]
	endpoints := []string{}
	// check if enpoint contains substituion strings
	if strings.Contains(verifier.Endpoint, "{$") {
		for _, matchSet := range matches {
			endpoint := verifier.Endpoint
			for k, v := range matchSet {
				// replace all the substitution strings with the actual values
				endpoint = strings.ReplaceAll(endpoint, "{$"+k+"}", v[0])
			}
			endpoints = append(endpoints, endpoint)
		}
	}
	endpoints = removeDuplicateStr(endpoints)
	fmt.Println("endpoints: ", endpoints)

	headersMap := map[string][]string{}
	for _, header := range verifier.Headers {
		key, value, found := strings.Cut(header, ":")
		if found {
			headersMap[key] = append(headersMap[key], strings.TrimLeft(value, " "))
		}
	}

	// now check headers
	for headerKey, headerValue := range headersMap {
		for _, matchSet := range matches {
			for k, v := range matchSet {
				vals := headersMap[headerKey]

				// check if header exists in vals already
				skip := false
				for _, val := range vals {
					if val == strings.ReplaceAll(headerValue[0], "{$"+k+"}", v[0]) {
						skip = true
					}
				}
				if skip {
					continue
				}

				headersMap[headerKey] = append(headersMap[headerKey],
					strings.ReplaceAll(headerValue[0], "{$"+k+"}", v[0]))
			}
		}
	}

	// finally, remove the first element of each header in the headerMap since that is the substitution string
	for headerKey, headerValue := range headersMap {
		// check if the header has a substitution strings
		if strings.Contains(headerValue[0], "{$") {
			headersMap[headerKey] = headerValue[1:]
		}
	}

	headerCombinations := generateHeaderCombinations(headersMap)
	// fmt.Println("header combinations: ", headerCombinations)

	g := new(errgroup.Group)
	resultsCh := make(chan detectors.Result, maxTotalMatches)
	for _, endpoint := range endpoints {
		for _, headerSet := range headerCombinations {
			fmt.Println("header set: ", headerSet, "endpoint: ", endpoint)
			g.Go(func() error {
				return c.createResultsDirect(ctx, endpoint, headerSet, true, resultsCh)
			})
		}
	}

	_ = g.Wait()
	close(resultsCh)

	for result := range resultsCh {
		// NOTE: I don't believe this is being set anywhere else, hence the map assignment.
		result.ExtraData = map[string]string{
			"name": c.GetName(),
		}
		results = append(results, result)
	}

	return results, nil
}

func (c *CustomRegexWebhook) createResultsDirect(ctx context.Context, endpoint string, headerSet map[string]string, verify bool, results chan<- detectors.Result) error {
	if common.IsDone(ctx) {
		// TODO: Log we're possibly leaving out results.
		return ctx.Err()
	}
	var raw string
	result := detectors.Result{
		DetectorType: detectorspb.DetectorType_CustomRegex,
		DetectorName: c.GetName(),
		Raw:          []byte(raw),
	}

	if !verify {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case results <- result:
			return nil
		}
	}
	if common.IsDone(ctx) {
		// TODO: Log we're possibly leaving out results.
		return ctx.Err()
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
	if err != nil {
        return err
	}
	for k, v := range headerSet {
		req.Header.Add(k, v)
	}
	res, err := httpClient.Do(req)
	if err != nil {
        return err
	}
	// TODO: Read response body.
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		result.Verified = true
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case results <- result:
		return nil
	}
}

func (c *CustomRegexWebhook) shouldDirectVerify() bool {
	verifier := c.GetVerify()[0]
	for _, header := range verifier.Headers {
		if strings.Contains(header, "{$") {
			return true
		}
	}
	if strings.Contains(verifier.Endpoint, "{$") {
		return true
	}
	return false

}

func (c *CustomRegexWebhook) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
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

	if c.shouldDirectVerify() {
		c.doDirectVerify(ctx, matches)
	}

	g := new(errgroup.Group)

	// Create result object and test for verification.
	resultsCh := make(chan detectors.Result, maxTotalMatches)
	for _, match := range matches {
		match := match
		g.Go(func() error {
			return c.createResults(ctx, match, verify, resultsCh)
		})
	}

	// Ignore any errors and collect as many of the results as we can.
	_ = g.Wait()
	close(resultsCh)

	for result := range resultsCh {
		// NOTE: I don't believe this is being set anywhere else, hence the map assignment.
		result.ExtraData = map[string]string{
			"name": c.GetName(),
		}
		results = append(results, result)
	}

	return results, nil
}

func (c *CustomRegexWebhook) createResults(ctx context.Context, match map[string][]string, verify bool, results chan<- detectors.Result) error {
	if common.IsDone(ctx) {
		// TODO: Log we're possibly leaving out results.
		return ctx.Err()
	}
	var raw string
	for _, values := range match {
		// values[0] contains the entire regex match.
		raw += values[0]
	}
	result := detectors.Result{
		DetectorType: detectorspb.DetectorType_CustomRegex,
		DetectorName: c.GetName(),
		Raw:          []byte(raw),
	}

	if !verify {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case results <- result:
			return nil
		}
	}
	// Verify via webhook.
	jsonBody, err := json.Marshal(map[string]map[string][]string{
		c.GetName(): match,
	})
	if err != nil {
		// This should never happen, but if it does, return nil to not
		// disrupt other verification.
		return nil
	}
	// Try each config until we successfully verify.
	for _, verifyConfig := range c.GetVerify() {
		if common.IsDone(ctx) {
			// TODO: Log we're possibly leaving out results.
			return ctx.Err()
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
			// fmt.Println("key", key, "value", value)
			// fmt.Println("jsonBody", string(jsonBody))
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

	select {
	case <-ctx.Done():
		return ctx.Err()
	case results <- result:
		return nil
	}
}

func (c *CustomRegexWebhook) Keywords() []string {
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
	fmt.Println("what the fuck is matches", matches)

	return matches
}

func (c *CustomRegexWebhook) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CustomRegex
}
