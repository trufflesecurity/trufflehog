package custom_detectors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

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
	for name, reg := range regex {
		if _, err := regexp.Compile(reg); err != nil {
			return fmt.Errorf("regex '%s': %w", name, err)
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
	for _, b := range body {
		matches := NewRegexVarString(b).variables
		for match := range matches {
			if _, ok := regex[match]; !ok {
				return fmt.Errorf("body %q contains an unknown variable", b)
			}
		}
	}
	return nil
}

// === Custom Validations ===

// ContainsDigit checks if string contains at least one digit
func ContainsDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		char := s[i]
		if char >= '0' && char <= '9' {
			return true
		}
	}

	return false
}

// ContainsLowercase checks if string contains at least one lowercase letter
func ContainsLowercase(s string) bool {
	for i := 0; i < len(s); i++ {
		char := s[i]
		if char >= 'a' && char <= 'z' {
			return true
		}
	}

	return false
}

// ContainsUppercase checks if string contains at least one uppercase letter
func ContainsUppercase(s string) bool {
	for i := 0; i < len(s); i++ {
		char := s[i]
		if char >= 'A' && char <= 'Z' {
			return true
		}
	}

	return false
}

// ContainsSpecialChar checks if string contains at least one special character
func ContainsSpecialChar(s string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	return strings.ContainsAny(s, specialChars)
}
