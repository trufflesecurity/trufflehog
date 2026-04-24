package pinecone

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVerifyTokenSuccess(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodGet {
				t.Fatalf("expected GET request, got %s", req.Method)
			}
			if req.URL.String() != "https://api.pinecone.io/indexes" {
				t.Fatalf("unexpected URL %s", req.URL.String())
			}
			if got := req.Header.Get("Api-Key"); got != "pcsk_test_secret" {
				t.Fatalf("unexpected api key header %q", got)
			}
			if got := req.Header.Get("X-Pinecone-Api-Version"); got != "2025-10" {
				t.Fatalf("unexpected api version header %q", got)
			}

			body := `{"indexes":[{"name":"example-index","host":"example-index-abc1234.svc.us-east1-aws.pinecone.io","metric":"cosine","status":{"ready":true,"state":"Ready"},"spec":{"serverless":{"cloud":"aws","region":"us-east-1"}}}]}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	verified, extraData, err := verifyToken(context.Background(), client, "pcsk_test_secret")
	if err != nil {
		t.Fatalf("verifyToken returned error: %v", err)
	}
	if !verified {
		t.Fatal("expected token to verify successfully")
	}
	if extraData["total_indexes"] != "1" {
		t.Fatalf("expected total_indexes=1, got %q", extraData["total_indexes"])
	}
	if extraData["project_id"] != "abc1234" {
		t.Fatalf("expected project_id=abc1234, got %q", extraData["project_id"])
	}
	if extraData["index_0_name"] != "example-index" {
		t.Fatalf("expected index_0_name to be populated, got %q", extraData["index_0_name"])
	}
}

func TestVerifyTokenRejectsMissingIndexesKey(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"projects":[]}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	verified, extraData, err := verifyToken(context.Background(), client, "pcsk_test_secret")
	if err == nil {
		t.Fatal("expected an error for malformed 200 response")
	}
	if !strings.Contains(err.Error(), "unexpected response body structure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected malformed 200 response to remain unverified")
	}
	if extraData != nil {
		t.Fatalf("expected no extra data, got %#v", extraData)
	}
}

func TestVerifyTokenRejectsInvalidIndexesPayload(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"indexes":{}}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	verified, extraData, err := verifyToken(context.Background(), client, "pcsk_test_secret")
	if err == nil {
		t.Fatal("expected a decode error for invalid indexes payload")
	}
	if !strings.Contains(err.Error(), "failed to decode 200 response") {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected invalid indexes payload to remain unverified")
	}
	if extraData != nil {
		t.Fatalf("expected no extra data, got %#v", extraData)
	}
}

func TestScannerFromDataPreservesMetadataOnVerificationError(t *testing.T) {
	token := "pcsk_abcd_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	scanner := Scanner{
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"indexes":{}}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}),
		},
	}

	results, err := scanner.FromData(context.Background(), true, []byte(token))
	if err != nil {
		t.Fatalf("FromData returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if results[0].Verified {
		t.Fatal("expected malformed verification response to keep result unverified")
	}
	if results[0].VerificationError() == nil {
		t.Fatal("expected malformed verification response to set a verification error")
	}
	if got := results[0].ExtraData["key_id"]; got != "abcd" {
		t.Fatalf("expected key_id=abcd, got %q", got)
	}
	if got := results[0].SecretParts["key"]; got != token {
		t.Fatalf("expected secret key part to be preserved, got %q", got)
	}
}
