package gcshmac

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	serviceAccountID = "GOOG1EQ7XKP3M2VRW8TZJ4LNB6HYC9DFA5SUG0EQ2RT7WX3KPMLNB4VZH8JCT"
	userAccountID    = "GOOGR7VXK3PL2QJ8MZWN4TBY"
	secret           = "bGoa+V7g/yqDXvKRqq+J" + "TFn4uQZbPiQJo4pf9RzJ"
)

func TestGCSHMAC_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "service account key under AWS env names",
			input: fmt.Sprintf("AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n", serviceAccountID, secret),
			want:  []string{serviceAccountID + ":" + secret},
		},
		{
			name:  "user account key",
			input: fmt.Sprintf("access_id: %s\nsecret: %s\n", userAccountID, secret),
			want:  []string{userAccountID + ":" + secret},
		},
		{
			name: "boto config block",
			input: fmt.Sprintf(`[Credentials]
gs_access_key_id = %s
gs_secret_access_key = %s`, serviceAccountID, secret),
			want: []string{serviceAccountID + ":" + secret},
		},
		{
			name:  "url-encoded secret",
			input: fmt.Sprintf("s3://%s:%s@storage.googleapis.com/bucket", serviceAccountID, strings.ReplaceAll(secret, "/", "%2F")),
			want:  []string{serviceAccountID + ":" + secret},
		},
		{
			name:  "AWS access key is not a GCS key",
			input: fmt.Sprintf("AWS_ACCESS_KEY_ID=AKIAQYLPMN5HHHFPZAM2\nAWS_SECRET_ACCESS_KEY=%s\n", secret),
			want:  nil,
		},
		{
			name:  "GOOG-prefixed identifier of the wrong length",
			input: fmt.Sprintf("GOOGR7VXK3PL2QJ8MZWN4TBYQ7XK\n%s\n", secret),
			want:  nil,
		},
		{
			name:  "unrelated GOOGLE variable",
			input: fmt.Sprintf("GOOGLE_APPLICATION_CREDENTIALS=/etc/key.json\nsecret=%s\n", secret),
			want:  nil,
		},
		{
			name:  "access ID without a secret",
			input: fmt.Sprintf("AWS_ACCESS_KEY_ID=%s\n", serviceAccountID),
			want:  nil,
		},
		{
			name:  "hex digest as secret is dropped when unverified",
			input: fmt.Sprintf("%s\n%s\n", serviceAccountID, "3f786850e387550fdab836ed7e6dc881de23001b"),
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, received %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.RawV2)] = struct{}{}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestGCSHMAC_AccountType(t *testing.T) {
	if got := accountType(serviceAccountID); got != "service_account" {
		t.Errorf("accountType(service account ID) = %q", got)
	}
	if got := accountType(userAccountID); got != "user_account" {
		t.Errorf("accountType(user account ID) = %q", got)
	}
}

func xmlErr(code string) string {
	return `<?xml version='1.0' encoding='UTF-8'?><Error><Code>` + code + `</Code><Message>m</Message></Error>`
}

func TestGCSHMAC_Verify(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      bool
	}{
		{"valid key", http.StatusOK, `<ListAllMyBucketsResult/>`, true, false},
		{"valid key without bucket list permission", http.StatusForbidden, xmlErr("AccessDenied"), true, false},
		{"unknown access ID", http.StatusForbidden, xmlErr("InvalidAccessKeyId"), false, false},
		{"wrong secret", http.StatusForbidden, xmlErr("SignatureDoesNotMatch"), false, false},
		{"server error is indeterminate", http.StatusInternalServerError, xmlErr("InternalError"), false, true},
		{"non-XML error is indeterminate", http.StatusBadGateway, "bad gateway", false, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer srv.Close()

			verified, err := verifyHMACKey(context.Background(), srv.Client(), srv.URL+"/", serviceAccountID, secret)

			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
			if (err != nil) != test.wantErr {
				t.Errorf("err = %v, wantErr %v", err, test.wantErr)
			}
			if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential="+serviceAccountID+"/") {
				t.Errorf("Authorization = %q, want SigV4 for %s", gotAuth, serviceAccountID)
			}
		})
	}
}
