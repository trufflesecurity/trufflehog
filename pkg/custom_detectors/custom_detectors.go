package custom_detectors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

// customRegex is a CustomRegex that is guaranteed to be valid.
type customRegex *custom_detectorspb.CustomRegex

func ValidateKeywords(keywords []string) error {
	if len(keywords) == 0 {
		return fmt.Errorf("no keywords")
	}

	for _, keyword := range keywords {
		if len(keyword) == 0 {
			return fmt.Errorf("empty keyword")
		}
	}
	return nil
}

func ValidateRegex(regex map[string]string) error {
	if len(regex) == 0 {
		return fmt.Errorf("no regex")
	}

	for _, r := range regex {
		if _, err := regexp.Compile(r); err != nil {
			return fmt.Errorf("invalid regex %q", r)
		}
	}

	return nil
}

func ValidateVerifyEndpoint(endpoint string, unsafe bool) error {
	if len(endpoint) == 0 {
		return fmt.Errorf("no endpoint")
	}

	if strings.HasPrefix(endpoint, "http://") && !unsafe {
		return fmt.Errorf("http endpoint must have unsafe=true")
	}
	return nil
}

func ValidateVerifyHeaders(headers []string) error {
	for _, header := range headers {
		if !strings.Contains(header, ":") {
			return fmt.Errorf("header %q must contain a colon", header)
		}
	}
	return nil
}

func ValidateVerifyRanges(ranges []string) error {
	const httpLowerRange = 100
	const httpUpperRange = 599

	for _, successRange := range ranges {
		if !strings.Contains(successRange, "-") {
			httpCode, err := strconv.Atoi(successRange)
			if err != nil {
				return fmt.Errorf("unable to convert http code to int %q", successRange)
			}

			if httpCode < httpLowerRange || httpCode > httpUpperRange {
				return fmt.Errorf("invalid http status code %q", successRange)
			}

			continue
		}

		httpRange := strings.Split(successRange, "-")
		if len(httpRange) != 2 {
			return fmt.Errorf("invalid range format %q", successRange)
		}

		lowerBound, err := strconv.Atoi(httpRange[0])
		if err != nil {
			return fmt.Errorf("unable to convert lower bound to int %q", successRange)
		}

		upperBound, err := strconv.Atoi(httpRange[1])
		if err != nil {
			return fmt.Errorf("unable to convert upper bound to int %q", successRange)
		}

		if lowerBound > upperBound {
			return fmt.Errorf("lower bound greater than upper bound on range %q", successRange)
		}

		if lowerBound < httpLowerRange || upperBound > httpUpperRange {
			return fmt.Errorf("invalid http status code range %q", successRange)
		}
	}
	return nil
}

func ValidateRegexVars(regex map[string]string, body ...string) error {
	r := regexp.MustCompile(`{(.+?)}`)
	for _, b := range body {
		matches := r.FindAllStringSubmatch(b, -1)

		for _, match := range matches {
			if _, ok := regex[match[1]]; !ok {
				return fmt.Errorf("body %q contains an unknown variable", b)
			}
		}
	}

	return nil
}

func NewCustomRegex(pb *custom_detectorspb.CustomRegex) (customRegex, error) {
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

		if err := ValidateVerifyRanges(verify.SuccessRanges); err != nil {
			return nil, err
		}

		if err := ValidateRegexVars(pb.Regex, append(verify.Headers, verify.Endpoint)...); err != nil {
			return nil, err
		}

	}

	return pb, nil
}
