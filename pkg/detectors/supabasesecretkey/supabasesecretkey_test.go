package supabasesecretkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Made-up keys in the documented layout. None of them belong to a real project.
// The prefix is split so secret scanners, including GitHub push protection, don't flag the source.
const (
	prefix      = "sb_" + "secret_"
	key1        = prefix + "Zq3vN8xKp2LmR7tYw4Hc9a_Fk2Lq-8x"
	key2        = prefix + "Ab-cD_eF9gH1iJ2kL3mN4o_P5q6R7s-"
	project1    = "abcdefghijklmnopqrst"
	project2    = "qwertyuiopasdfghjklz"
	project1URL = "https://" + project1 + ".supabase.co"
	project2URL = "https://" + project2 + ".supabase.co"
)

func TestSupabaseSecretKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "env file line",
			input: "SUPABASE_SECRET_KEY=" + key1,
			want:  []string{key1},
		},
		{
			name:  "key and project URL in code",
			input: fmt.Sprintf("const supabase = createClient('%s', '%s')", project1URL, key1),
			want:  []string{key1 + project1URL},
		},
		{
			name:  "key ending in a dash, in json",
			input: fmt.Sprintf(`{"serviceKey": "%s"}`, key2),
			want:  []string{key2},
		},
		{
			name:  "adjacent keys separated by one character",
			input: key1 + "," + key2,
			want:  []string{key1, key2},
		},
		{
			name: "two keys and two projects pair every key with every project",
			input: fmt.Sprintf("SUPABASE_URL=%s\nOTHER_URL=%s/rest/v1\nKEY_A=%s\nKEY_B=%s",
				project1URL, project2URL, key1, key2),
			want: []string{key1 + project1URL, key1 + project2URL, key2 + project1URL, key2 + project2URL},
		},
		{
			name:  "same key twice is reported once",
			input: key1 + "\n" + key1,
			want:  []string{key1},
		},
		{
			name:  "supabase.com is not a project URL",
			input: "see https://abcdefghijklmnopqrst.supabase.com for " + key1,
			want:  []string{key1},
		},
		{
			name:  "postgres host names the same project",
			input: fmt.Sprintf("DATABASE_URL=postgresql://postgres@db.%s.supabase.co:5432/postgres\nKEY=%s", project1, key1),
			want:  []string{key1 + project1URL},
		},
		{
			name:  "key after a literal escaped newline in json",
			input: `{"env": "A=1\n` + key1 + `"}`,
			want:  []string{key1},
		},
		{
			name:  "key glued to the end of a variable name",
			input: "SUPABASE_KEY_" + key1,
			want:  []string{key1},
		},
		{
			name:  "longer run of key characters",
			input: "token=" + key1 + "Xy",
			want:  nil,
		},
		{
			name:  "followed by a dash",
			input: "token=" + key1 + "-",
			want:  nil,
		},
		{
			name:  "followed by an underscore",
			input: "token=" + key1 + "_",
			want:  nil,
		},
		{
			name:  "no underscore before the checksum",
			input: "token=" + prefix + "Zq3vN8xKp2LmR7tYw4Hc9aXFk2Lq-8x",
			want:  nil,
		},
		{
			name:  "random part too short",
			input: "token=" + prefix + "Zq3vN8xKp2LmR7tYw4Hc9_Fk2Lq-8x",
			want:  nil,
		},
		{
			name:  "placeholder from the docs",
			input: "SUPABASE_SECRET_KEY=sb_secret_xxx",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
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
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
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

func TestSupabaseSecretKey_Verify(t *testing.T) {
	errTransport := errors.New("transport failure")

	tests := []struct {
		name         string
		responseCode int
		transportErr error
		wantVerified bool
		wantErr      string
	}{
		{name: "200 OK - verified", responseCode: http.StatusOK, wantVerified: true},
		{name: "401 Unauthorized - unverified", responseCode: http.StatusUnauthorized},
		{name: "302 Found - not followed, verification error", responseCode: http.StatusFound, wantErr: "unexpected HTTP response status 302"},
		{name: "403 Forbidden - verification error", responseCode: http.StatusForbidden, wantErr: "unexpected HTTP response status 403"},
		{name: "404 Not Found - verification error", responseCode: http.StatusNotFound, wantErr: "unexpected HTTP response status 404"},
		{name: "429 Too Many Requests - verification error", responseCode: http.StatusTooManyRequests, wantErr: "unexpected HTTP response status 429"},
		{name: "500 Internal Server Error - verification error", responseCode: http.StatusInternalServerError, wantErr: "unexpected HTTP response status 500"},
		{name: "transport failure - verification error", transportErr: errTransport, wantErr: errTransport.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			s := Scanner{client: &http.Client{Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					requests++
					if req.Method != http.MethodGet {
						t.Errorf("method = %s, want GET", req.Method)
					}
					if got := req.URL.String(); got != project1URL+"/auth/v1/settings" {
						t.Errorf("url = %s", got)
					}
					if got := req.Header.Get("apikey"); got != key1 {
						t.Errorf("apikey = %q", got)
					}
					if got := req.Header.Get("Authorization"); got != "" {
						t.Errorf("Authorization = %q, want it unset", got)
					}
					if tt.transportErr != nil {
						return nil, tt.transportErr
					}
					return &http.Response{
						Request:    req,
						StatusCode: tt.responseCode,
						Header:     http.Header{"Location": []string{"https://elsewhere.example/"}},
						Body:       io.NopCloser(strings.NewReader("{}")),
					}, nil
				},
			}}}

			input := fmt.Sprintf("SUPABASE_URL=%s\nSUPABASE_SECRET_KEY=%s", project1URL, key1)
			results, err := s.FromData(context.Background(), true, []byte(input))
			if err != nil {
				t.Fatalf("FromData error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			r := results[0]

			if r.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, tt.wantVerified)
			}
			verificationErr := r.VerificationError()
			if tt.wantErr == "" {
				if verificationErr != nil {
					t.Errorf("unexpected verification error: %v", verificationErr)
				}
			} else if verificationErr == nil || !strings.Contains(verificationErr.Error(), tt.wantErr) {
				t.Errorf("verification error = %v, want it to contain %q", verificationErr, tt.wantErr)
			}
			if requests != 1 {
				t.Errorf("made %d requests, want 1", requests)
			}
			wantParts := map[string]string{"key": key1, "url": project1URL}
			if diff := cmp.Diff(wantParts, r.SecretParts); diff != "" {
				t.Errorf("SecretParts diff: (-want +got)\n%s", diff)
			}
			if got := string(r.RawV2); got != key1+project1URL {
				t.Errorf("RawV2 = %q", got)
			}
			if got := r.ExtraData["rotation_guide"]; got != "https://supabase.com/docs/guides/api/api-keys" {
				t.Errorf("rotation_guide = %q", got)
			}
		})
	}
}

func TestSupabaseSecretKey_VerifyPairsKeyWithEachProject(t *testing.T) {
	s := Scanner{client: &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			status := http.StatusUnauthorized
			if req.URL.Host == project1+".supabase.co" {
				status = http.StatusOK
			}
			return &http.Response{Request: req, StatusCode: status, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		},
	}}}

	input := fmt.Sprintf("A=%s\nB=%s\nKEY=%s", project1URL, project2URL, key1)
	results, err := s.FromData(context.Background(), true, []byte(input))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}

	got := make(map[string]bool, len(results))
	for _, r := range results {
		if r.VerificationError() != nil {
			t.Errorf("unexpected verification error for %s: %v", r.SecretParts["url"], r.VerificationError())
		}
		got[r.SecretParts["url"]] = r.Verified
	}
	want := map[string]bool{project1URL: true, project2URL: false}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("verified by project diff: (-want +got)\n%s", diff)
	}
}

func TestSupabaseSecretKey_NoVerify(t *testing.T) {
	s := Scanner{client: &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			t.Errorf("unexpected request to %s", req.URL)
			return nil, errors.New("unexpected request")
		},
	}}}

	for _, input := range []string{"KEY=" + key1, project1URL + " " + key1} {
		results, err := s.FromData(context.Background(), false, []byte(input))
		if err != nil {
			t.Fatalf("FromData error = %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1", len(results))
		}
		if results[0].Verified || results[0].VerificationError() != nil {
			t.Errorf("Verified = %v, verification error = %v; want false, nil",
				results[0].Verified, results[0].VerificationError())
		}
	}
}

func TestSupabaseSecretKey_VerifyWithoutProject(t *testing.T) {
	s := Scanner{client: &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			t.Errorf("unexpected request to %s", req.URL)
			return nil, errors.New("unexpected request")
		},
	}}}

	results, err := s.FromData(context.Background(), true, []byte("SUPABASE_SECRET_KEY="+key1))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Verified {
		t.Errorf("Verified = true, want false")
	}
	// SetVerificationError rewraps the error to redact secrets, so compare messages.
	if err := r.VerificationError(); err == nil || err.Error() != errNoProject.Error() {
		t.Errorf("verification error = %v, want %v", r.VerificationError(), errNoProject)
	}
	if diff := cmp.Diff(map[string]string{"key": key1}, r.SecretParts); diff != "" {
		t.Errorf("SecretParts diff: (-want +got)\n%s", diff)
	}
}
