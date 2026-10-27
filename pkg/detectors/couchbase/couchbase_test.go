package couchbase

import (
	"bytes"
	"context"
	"errors"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// unreachableConnString points gocb at a local port nothing listens on. gocb.Connect succeeds
// immediately (it bootstraps in the background) and pings never find a healthy endpoint, which
// exercises the full connect, ping, close lifecycle without network access or a real cluster.
const unreachableConnString = "couchbases://127.0.0.1:1"

// gocbGoroutines counts live goroutines whose stacks run through gocb or gocbcore. Each open
// gocb.Cluster keeps several of these alive until Close, so a nonzero count after verification
// returns means a client leaked.
func gocbGoroutines() int {
	var buf bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)
	count := 0
	for _, stack := range strings.Split(buf.String(), "\n\n") {
		if strings.Contains(stack, "github.com/couchbase/gocb") {
			count++
		}
	}
	return count
}

// requireNoGocbGoroutines waits briefly for Close to finish tearing down background goroutines,
// then fails if any gocb goroutines remain.
func requireNoGocbGoroutines(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for gocbGoroutines() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := gocbGoroutines(); n > 0 {
		t.Fatalf("%d gocb goroutines still running; a cluster was not closed", n)
	}
}

func TestVerifyCouchBase_ContextCancellationStopsVerificationAndClosesCluster(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	verified, err := verifyCouchBase(ctx, "user", "Passw0rd!", unreachableConnString)
	elapsed := time.Since(start)

	if verified {
		t.Errorf("expected unverified result against an unreachable cluster")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
	// The ping's own timeout is 5s; finishing well under it shows ctx ended the ping.
	if elapsed > 2*time.Second {
		t.Errorf("verification took %s after ctx expired at 200ms", elapsed)
	}
	requireNoGocbGoroutines(t)
}

func TestVerifyCouchBase_ClosesClusterWhenNoEndpointIsHealthy(t *testing.T) {
	verified, err := verifyCouchBase(context.Background(), "user", "Passw0rd!", unreachableConnString)
	if verified {
		t.Errorf("expected unverified result against an unreachable cluster")
	}
	if err != nil {
		t.Errorf("expected no error when ping completes without a healthy endpoint, got %v", err)
	}
	requireNoGocbGoroutines(t)
}

func TestVerifyCouchBase_EndedContextSkipsConnecting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verified, err := verifyCouchBase(ctx, "user", "Passw0rd!", unreachableConnString)
	if verified {
		t.Errorf("expected unverified result when ctx has already ended")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	// Checked immediately rather than with requireNoGocbGoroutines: no client should ever have
	// been built, so there is nothing to wait for.
	if n := gocbGoroutines(); n > 0 {
		t.Errorf("%d gocb goroutines running; a client was built after ctx ended", n)
	}
}

func TestCouchBase_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				# Configuration File: config.yaml
				database:
					host: $DB_HOST
					port: $DB_PORT
					username: $DB_USERNAME
					password: $DB_PASS  # IMPORTANT: Do not share this password publicly

				api:
					auth_type: "Password"
					in: "Configuration"
					couchbase_domain: "couchbases://cb.testing.cloud.couchbase.com"
					couchbase_username: "usrpS@d>p"
					couchbase_password: "passwordU+2028 rf\@V[4,L/?2}"
					base_url: "https://$couchbase_domain/v1/user"

				# Notes:
				# - Remember to rotate the secret every 90 days.
				# - The above credentials should only be used in a secure environment.
			`,
			want: []string{
				"usrpS@d>p:passwordU+2028@couchbases://cb.testing.cloud.couchbase.com",
				"$DB_USERNAME:passwordU+2028@couchbases://cb.testing.cloud.couchbase.com",
			},
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
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
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
