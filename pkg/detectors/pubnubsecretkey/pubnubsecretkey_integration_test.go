//go:build detectors
// +build detectors

package pubnubsecretkey

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestPubNubSecretKey_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretKey := testSecrets.MustGetField("PUBNUB_SECRET_KEY")
	publishKey := testSecrets.MustGetField("PUBNUB_PUBLISH_KEY")
	subscribeKey := testSecrets.MustGetField("PUBNUB_SUBSCRIBE_KEY")
	inactiveSecretKey := testSecrets.MustGetField("PUBNUB_SECRET_KEY_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("pubnub secret=%s publish=%s subscribe=%s", secretKey, publishKey, subscribeKey)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_PubNubSecretKey,
					Verified:     true,
					RawV2:        []byte(publishKey + "/" + subscribeKey + "/" + secretKey),
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("pubnub secret=%s publish=%s subscribe=%s", inactiveSecretKey, publishKey, subscribeKey)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_PubNubSecretKey,
					Verified:     false,
					RawV2:        []byte(publishKey + "/" + subscribeKey + "/" + inactiveSecretKey),
				},
			},
			wantErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("pubnub secret=%s publish=%s subscribe=%s", secretKey, publishKey, subscribeKey)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detector_typepb.DetectorType_PubNubSecretKey,
					Verified:     false,
					RawV2:        []byte(publishKey + "/" + subscribeKey + "/" + secretKey),
				}
				r.SetVerificationError(fmt.Errorf("context deadline exceeded"), secretKey)
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
		{
			name: "found, unexpected api response",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("pubnub secret=%s publish=%s subscribe=%s", secretKey, publishKey, subscribeKey)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detector_typepb.DetectorType_PubNubSecretKey,
					Verified:     false,
					RawV2:        []byte(publishKey + "/" + subscribeKey + "/" + secretKey),
				}
				r.SetVerificationError(fmt.Errorf("unexpected HTTP response status 404"), secretKey)
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("no pubnub credentials here"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("PubNubSecretKey.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if tt.want[i].VerificationError() != nil {
					if got[i].VerificationError() == nil {
						t.Fatalf("wantVerificationError = %v, got no verification error", tt.want[i].VerificationError())
					}
					if !strings.Contains(got[i].VerificationError().Error(), tt.want[i].VerificationError().Error()) {
						t.Fatalf("wantVerificationError = %v, verification error = %v", tt.want[i].VerificationError(), got[i].VerificationError())
					}
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError", "SecretParts")
			ignoreUnexported := cmpopts.IgnoreUnexported(detectors.Result{})
			if diff := cmp.Diff(got, tt.want, ignoreOpts, ignoreUnexported); diff != "" {
				t.Errorf("PubNubSecretKey.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
