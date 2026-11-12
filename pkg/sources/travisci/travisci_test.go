package travisci

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_Scan(t *testing.T) {
	ctx := context.Background()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("TRAVISCI_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.TravisCI
	}
	tests := []struct {
		name               string
		init               init
		wantSourceMetadata *source_metadatapb.MetaData
		wantErr            bool
	}{
		{
			name: "get a chunk",
			init: init{
				name: "example repo",
				connection: &sourcespb.TravisCI{
					Credential: &sourcespb.TravisCI_Token{
						Token: token,
					},
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_TravisCI{
					TravisCI: &source_metadatapb.TravisCI{
						Username:    "truffle-sandbox",
						Repository:  "test-repo",
						BuildNumber: "1",
						JobNumber:   "1.1",
						Link:        "https://app.travis-ci.com/github/truffle-sandbox/test-repo/jobs/611053994",
						Public:      false,
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 5)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
			}

			reporter := sourcestest.TestReporter{}
			s.returnAfterFirstChunk = true

			err = s.Enumerate(ctx, &reporter)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Source.Enumerate() error = %v, wantErr %v", err, tt.wantErr)
			}

			for _, unit := range reporter.Units {
				err = s.ChunkUnit(ctx, unit, &reporter)
				if (err != nil) != tt.wantErr {
					t.Fatalf("Source.ChunkUnit() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

			for _, chunk := range reporter.Chunks {
				if diff := pretty.Compare(chunk.SourceMetadata, tt.wantSourceMetadata); diff != "" {
					t.Fatalf("comparing chunks: %s diff: (-got +want)\n%s", tt.name, diff)
				}
			}
		})
	}
}

// fakeTravis serves the parts of the Travis CI API the source uses: one repo with a
// build that has no jobs, then a build with two jobs, one of which has no log yet.
// The first /user call returns a 503, which the client retries.
func fakeTravis(t *testing.T, secretLog string) *httptest.Server {
	t.Helper()
	var userCalls atomic.Int32
	write := func(w http.ResponseWriter, body any) {
		_ = json.NewEncoder(w).Encode(body)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the client leaves out offset=0
		firstPage := r.URL.Query().Get("offset") == ""
		switch r.URL.Path {
		case "/user":
			if userCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			write(w, map[string]any{"id": 1, "login": "org"})
		case "/repos":
			repos := []map[string]any{}
			if firstPage {
				repos = append(repos, map[string]any{"id": 42, "name": "app", "slug": "org/app", "private": true})
			}
			write(w, map[string]any{"repositories": repos})
		case "/repo/42":
			write(w, map[string]any{"id": 42, "name": "app", "slug": "org/app", "private": true})
		case "/repo/org/app/builds":
			builds := []map[string]any{}
			if firstPage {
				builds = append(builds,
					map[string]any{"id": 11, "number": "1"},
					map[string]any{"id": 12, "number": "2"},
				)
			}
			write(w, map[string]any{"builds": builds})
		case "/build/11/jobs":
			write(w, map[string]any{"jobs": []any{}})
		case "/build/12/jobs":
			write(w, map[string]any{"jobs": []map[string]any{
				{"id": 100, "number": "2.1", "owner": map[string]any{"login": "org"}},
				{"id": 101, "number": "2.2", "owner": map[string]any{"login": "org"}},
			}})
		case "/job/100/log":
			write(w, map[string]any{"id": 1000, "content": secretLog})
		case "/job/101/log":
			write(w, map[string]any{"id": 1001})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSource_DebugLogging(t *testing.T) {
	const (
		testSecret = "travisdebuglogtestsecret"
		testToken  = "travisdebuglogtesttoken"
	)

	runSource := func(t *testing.T, debug bool) []observer.LoggedEntry {
		t.Helper()
		srv := fakeTravis(t, "token = "+testSecret)
		defer srv.Close()
		oldBaseURL := baseURL
		baseURL = srv.URL + "/"
		defer func() { baseURL = oldBaseURL }()

		ctx, logs := logtest.SourceContext(debug)
		conn, err := anypb.New(&sourcespb.TravisCI{Credential: &sourcespb.TravisCI_Token{Token: testToken}})
		require.NoError(t, err)

		s := Source{}
		require.NoError(t, s.Init(ctx, "test source", 1, 1, false, conn, 1))
		if debug {
			logtest.CheckInitLine(t, logs.All())
		}

		reporter := sourcestest.TestReporter{}
		require.NoError(t, s.Enumerate(ctx, &reporter))
		for _, unit := range reporter.Units {
			require.NoError(t, s.ChunkUnit(ctx, unit, &reporter))
		}
		assert.Empty(t, reporter.UnitErrs)
		assert.Empty(t, reporter.ChunkErrs)

		// the build with no jobs does not stop the next build, and the job with no
		// log is skipped
		var jobs []string
		for _, chunk := range reporter.Chunks {
			jobs = append(jobs, chunk.SourceMetadata.GetTravisCI().GetJobNumber())
		}
		assert.Equal(t, []string{"2.1"}, jobs)
		return logs.All()
	}

	t.Run("debug on", func(t *testing.T) {
		logtest.CheckSourceLines(t, runSource(t, true), testSecret, testToken)
	})

	t.Run("debug off", func(t *testing.T) {
		logtest.CheckNoDebugLines(t, runSource(t, false))
	})
}
