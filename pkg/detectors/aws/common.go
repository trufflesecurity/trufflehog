package aws

import regexp "github.com/wasilibs/go-re2"

const (
	RequiredIdEntropy     = 3.0
	RequiredSecretEntropy = 4.25
)

var SecretPat = regexp.MustCompile(`(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)`)

type IdentityResponse struct {
	GetCallerIdentityResponse struct {
		GetCallerIdentityResult struct {
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
			UserID  string `json:"UserId"`
		} `json:"GetCallerIdentityResult"`
		ResponseMetadata struct {
			RequestID string `json:"RequestId"`
		} `json:"ResponseMetadata"`
	} `json:"GetCallerIdentityResponse"`
}

type Error struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

type ErrorResponseBody struct {
	Error Error `json:"Error"`
}
