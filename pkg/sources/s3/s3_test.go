package s3

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
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
