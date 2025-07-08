//go:build detectors
// +build detectors

package snowflake

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestSnowflake_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	accountIdentifier := testSecrets.MustGetField("SNOWFLAKE_ACCOUNT")
	username := testSecrets.MustGetField("SNOWFLAKE_USERNAME")
	password := testSecrets.MustGetField("SNOWFLAKE_PASS")
	inactivePassword := testSecrets.MustGetField("SNOWFLAKE_PASS_INACTIVE")

	// Create a context with a past deadline to simulate DeadlineExceeded error
	pastTime := time.Now().Add(-time.Second) // Set the deadline in the past
	errorCtx, cancel := context.WithDeadline(context.Background(), pastTime)
	defer cancel()

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", accountIdentifier, username, password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Snowflake,
					Verified:     true,
					ExtraData: map[string]string{
						"account":  accountIdentifier,
						"username": username,
					},
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", accountIdentifier, username, inactivePassword)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Snowflake,
					Verified:     false,
					ExtraData: map[string]string{
						"account":  accountIdentifier,
						"username": username,
					},
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, indeterminate error (timeout)",
			s:    Scanner{},
			args: args{
				ctx:    errorCtx,
				data:   []byte(fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", accountIdentifier, username, password)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Snowflake,
					ExtraData: map[string]string{
						"account":  accountIdentifier,
						"username": username,
					},
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Snowflake.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			keysToCopy := []string{"account", "username"}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}

				got[i].ExtraData = newMap(got[i].ExtraData, keysToCopy)
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError", "primarySecret")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Snowflake.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func newMap(extraMap map[string]string, keysToCopy []string) map[string]string {
	newExtraDataMap := make(map[string]string)
	for _, key := range keysToCopy {
		if value, ok := extraMap[key]; ok {
			newExtraDataMap[key] = value
		}
	}
	return newExtraDataMap
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
