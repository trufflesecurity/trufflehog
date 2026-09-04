package s3

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Init_IncludeAndIgnoreBucketsError(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    "ignored for test",
				Secret: "ignore for test",
			},
		},
		Buckets:       []string{"a"},
		IgnoreBuckets: []string{"b"},
	})
	assert.NoError(t, err)

	s := Source{}
	err = s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1)

	assert.Error(t, err)
}

func TestSource_ListErrorsAreExpected(t *testing.T) {
	tests := []struct {
		name    string
		role    string
		buckets []string
		want    bool
	}{
		{
			name: "no role, no explicit buckets",
			want: false,
		},
		{
			name:    "no role, explicit buckets",
			buckets: []string{"bucket-a"},
			want:    false,
		},
		{
			name: "role without explicit buckets, denials are expected",
			role: "arn:aws:iam::123456789012:role/some-role",
			want: true,
		},
		{
			name:    "role with explicit buckets, denials are errors",
			role:    "arn:aws:iam::123456789012:role/some-role",
			buckets: []string{"bucket-a"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := anypb.New(&sourcespb.S3{
				Credential: &sourcespb.S3_AccessKey{
					AccessKey: &credentialspb.KeySecret{
						Key:    "ignored for test",
						Secret: "ignored for test",
					},
				},
				Buckets: tt.buckets,
				Roles:   []string{tt.role},
			})
			require.NoError(t, err)

			s := Source{}
			require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

			assert.Equal(t, tt.want, s.listErrorsAreExpected(tt.role))
		})
	}
}

func TestSource_ScanBucketsReportsCumulativeObjectCount(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
	})
	require.NoError(t, err)

	s := Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	// Simulate a later role pass after an earlier pass already scanned three
	// objects. The pass below scans no buckets, so the completion message must
	// still report the cumulative total rather than resetting to zero.
	totalObjectCount := uint64(3)
	require.NoError(t, s.scanBuckets(context.Background(), nil, "", nil, make(chan *sources.Chunk, 1), &totalObjectCount))

	assert.Equal(t, uint64(3), totalObjectCount)
	assert.Contains(t, s.Message, "3 objects scanned")
}

// accessDeniedListServer stands in for S3 and always returns ListObjectsV2 AccessDenied.
// Used to reproduce a configured bucket the identity cannot list, without AWS.
func accessDeniedListServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	}))
}

func TestChunkUnitReturnsErrorWhenConfiguredBucketListIsDenied(t *testing.T) {
	srv := accessDeniedListServer()
	t.Cleanup(srv.Close)

	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   srv.URL,
		Buckets:    []string{"private-bucket"},
	})
	require.NoError(t, err)

	s := Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	err = s.ChunkUnit(context.Background(), S3SourceUnit{Bucket: "private-bucket"}, sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)})
	require.Error(t, err)
	assert.ErrorContains(t, err, `could not list objects in bucket "private-bucket"`)
}

func TestScanBucketSwallowsExpectedRoleEnumerationDenials(t *testing.T) {
	srv := accessDeniedListServer()
	t.Cleanup(srv.Close)

	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   srv.URL,
	})
	require.NoError(t, err)

	s := Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	client, err := s.newClient(context.Background(), s.defaultRegion(), "")
	require.NoError(t, err)

	_, err = s.scanBucket(
		context.Background(),
		client,
		"arn:aws:iam::123456789012:role/some-role",
		"denied-bucket",
		sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)},
		nil,
		NewCheckpointer(context.Background(), &s.Progress, false),
	)
	require.NoError(t, err)
}

func TestSource_Chunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.S3
		setEnv     map[string]string
	}
	tests := []struct {
		name          string
		init          init
		wantErr       bool
		wantChunkData string
	}{
		{
			name: "gets chunks",
			init: init{
				connection: &sourcespb.S3{
					Credential: &sourcespb.S3_AccessKey{
						AccessKey: &credentialspb.KeySecret{
							Key:    s3key,
							Secret: s3secret,
						},
					},
					Buckets: []string{"truffletestbucket-s3-tests"},
				},
			},
			wantErr:       false,
			wantChunkData: `W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lkID0gQUtJQTM1T0hYMkRTT1pHNjQ3TkgKYXdzX3NlY3JldF9hY2Nlc3Nfa2V5ID0gUXk5OVMrWkIvQ1dsRk50eFBBaWQ3Z0d6dnNyWGhCQjd1ckFDQUxwWgpvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`,
		},
		{
			name: "gets chunks after assuming role",
			// This test will attempt to scan every bucket in the account, but the role policy blocks access to every
			// bucket except the one we want. This (expected behavior) causes errors in the test log output, but these
			// errors shouldn't actually cause test failures.
			init: init{
				connection: &sourcespb.S3{
					Roles: []string{"arn:aws:iam::619888638459:role/s3-test-assume-role"},
				},
				setEnv: map[string]string{
					"AWS_ACCESS_KEY_ID":     s3key,
					"AWS_SECRET_ACCESS_KEY": s3secret,
				},
			},
			wantErr:       false,
			wantChunkData: `W2RlZmF1bHRdCmF3c19zZWNyZXRfYWNjZXNzX2tleSA9IFF5OTlTK1pCL0NXbEZOdHhQQWlkN2dHenZzclhoQkI3dXJBQ0FMcFoKYXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMzVPSFgyRFNPWkc2NDdOSApvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "gets chunks after assuming role" {
				t.Skip("skipping until our test environment stabilizes enough that we know how we're going to handle this")
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()

			for k, v := range tt.init.setEnv {
				t.Setenv(k, v)
			}

			s := Source{}
			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					os.Exit(1)
				}
			}()

			waitFn := func() {
				receivedFirstChunk := false
				for {
					select {
					case <-ctx.Done():
						t.Errorf("TestSource_Chunks timed out: %v", ctx.Err())
						return
					case gotChunk, ok := <-chunksCh:
						if !ok {
							t.Logf("Source.Chunks() finished, channel closed")
							assert.Equal(t, "", s.GetProgress().EncodedResumeInfo)
							assert.Equal(t, int64(100), s.GetProgress().PercentComplete)
							return
						}
						if receivedFirstChunk {
							// wantChunkData is the first chunk data. After the first chunk has
							// been received and matched below, we want to drain chunksCh
							// so Source.Chunks() can finish completely.
							continue
						}

						receivedFirstChunk = true
						wantData, _ := base64.StdEncoding.DecodeString(tt.wantChunkData)

						if diff := pretty.Compare(gotChunk.Data, wantData); diff != "" {
							t.Logf("%s: Source.Chunks() diff: (-got +want)\n%s", tt.name, diff)
						}
					}
				}
			}
			waitFn()
		})
	}
}

func TestSource_UnmarshalSourceUnit(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/my-role"

	// envelope mirrors the JSON shape thog persists between the enumerate and
	// scan passes: the SourceUnit proto marshalled with encoding/json, where
	// unit_data (if present) is the original unit as base64-encoded bytes.
	type envelope struct {
		ID       string `json:"id"`
		Kind     string `json:"kind,omitempty"`
		Display  string `json:"display,omitempty"`
		UnitData string `json:"unit_data,omitempty"`
	}

	marshalEnvelope := func(t *testing.T, id string, kind string, unit *S3SourceUnit) []byte {
		t.Helper()
		env := envelope{ID: id, Kind: kind, Display: id}
		if unit != nil {
			raw, err := json.Marshal(unit)
			require.NoError(t, err)
			env.UnitData = base64.StdEncoding.EncodeToString(raw)
		}
		data, err := json.Marshal(env)
		require.NoError(t, err)
		return data
	}

	tests := []struct {
		name     string
		data     []byte
		wantUnit S3SourceUnit
		wantErr  bool
	}{
		{
			name:     "bare unit, role-bearing ARN",
			data:     []byte(`{"Bucket":"my-test-bucket","Role":"` + roleARN + `"}`),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN},
		},
		{
			name:     "bare unit, role-less",
			data:     []byte(`{"Bucket":"my-test-bucket"}`),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket"},
		},
		{
			name: "envelope with unit_data, role-bearing",
			data: marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", roleARN), "bucket",
				&S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN}),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN},
		},
		{
			name: "envelope with unit_data, role-less",
			data: marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", ""), "bucket",
				&S3SourceUnit{Bucket: "my-test-bucket"}),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket"},
		},
		{
			name:     "envelope without unit_data, role-bearing, rebuilt from id",
			data:     marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", roleARN), "bucket", nil),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN},
		},
		{
			name:     "envelope without unit_data, role-less, rebuilt from id",
			data:     marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", ""), "bucket", nil),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket"},
		},
		{
			// A CommonSourceUnit-shaped bare unit from another source also has
			// an "id" field; only S3's own "bucket" kind may trigger the
			// envelope id-rebuild path, or this would be misread as a bucket.
			name:    "bare unit from another source is rejected, not misread as an envelope",
			data:    []byte(`{"kind":"repository","id":"some-repo-id"}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}
			unit, err := s.UnmarshalSourceUnit(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "UnmarshalSourceUnit should not return an error")

			s3Unit, ok := unit.(S3SourceUnit)
			require.True(t, ok, "Unmarshaled unit should be of type S3SourceUnit")
			assert.Equal(t, tt.wantUnit, s3Unit)
		})
	}
}

func TestSource_ObjectLink(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name: "aws",
			want: "https://my-bucket.s3.eu-west-1.amazonaws.com/dir/key.txt",
		},
		{
			name:     "custom endpoint",
			endpoint: "https://s3.internal.example.com",
			want:     "https://s3.internal.example.com/my-bucket/dir/key.txt",
		},
		{
			name:     "custom endpoint with trailing slash",
			endpoint: "https://s3.internal.example.com/",
			want:     "https://s3.internal.example.com/my-bucket/dir/key.txt",
		},
		{
			name:     "custom endpoint with port and base path",
			endpoint: "http://minio.test:9000/base",
			want:     "http://minio.test:9000/base/my-bucket/dir/key.txt",
		},
		{
			name:     "endpoint without a scheme is assumed https",
			endpoint: "s3.internal.example.com",
			want:     "https://s3.internal.example.com/my-bucket/dir/key.txt",
		},
		{
			name:     "host and port without a scheme is assumed https",
			endpoint: "s3.internal.example.com:9000",
			want:     "https://s3.internal.example.com:9000/my-bucket/dir/key.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := anypb.New(&sourcespb.S3{
				Credential: &sourcespb.S3_Unauthenticated{},
				Endpoint:   tt.endpoint,
			})
			require.NoError(t, err)

			s := Source{}
			require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

			assert.Equal(t, tt.want, s.objectLink("my-bucket", "eu-west-1", "dir/key.txt"))
		})
	}
}

func TestSource_Init_InvalidEndpoint(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   "https://s3.internal.example.com:not-a-port",
	})
	require.NoError(t, err)

	s := Source{}
	assert.ErrorContains(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1), "endpoint")
}

func TestSource_ClientAddressing(t *testing.T) {
	tests := []struct {
		name          string
		conn          *sourcespb.S3
		wantRegion    string
		wantEndpoint  *string
		wantPathStyle bool
	}{
		{
			name:       "aws defaults",
			conn:       &sourcespb.S3{},
			wantRegion: defaultAWSRegion,
		},
		{
			name:       "explicit region without endpoint",
			conn:       &sourcespb.S3{Region: "ap-south-1"},
			wantRegion: "ap-south-1",
		},
		{
			name:          "custom endpoint implies path style",
			conn:          &sourcespb.S3{Endpoint: "https://s3.internal.example.com"},
			wantRegion:    defaultAWSRegion,
			wantEndpoint:  aws.String("https://s3.internal.example.com"),
			wantPathStyle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.conn.Credential = &sourcespb.S3_Unauthenticated{}
			conn, err := anypb.New(tt.conn)
			require.NoError(t, err)

			s := Source{}
			require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

			client, err := s.newClient(context.Background(), s.defaultRegion(), "")
			require.NoError(t, err)

			opts := client.Options()
			assert.Equal(t, tt.wantRegion, opts.Region)
			assert.Equal(t, tt.wantEndpoint, opts.BaseEndpoint)
			assert.Equal(t, tt.wantPathStyle, opts.UsePathStyle)
		})
	}
}
