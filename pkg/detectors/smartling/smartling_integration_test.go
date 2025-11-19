//go:build detectors
// +build detectors

package smartling

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestSmartling_FromChunk(t *testing.T) {

	// TODO: These are dummy credentials because we are mocking the API call to Smartling
	// Replace this with getting actual credentials from GCP vault once we have access to
	// an actual Smartling account and can make direct API calls
	userId := "bxraiavfkoirvbzhlhvwggnzuouwjp"
	secret := "aprb039cirfv071nqagvb22f3rWW^7qc802dle3rqeija66dkb1ulaa"
	inactiveUserId := "einnwiufkduvcizimcnwnnggymexoy"
	inactiveSecret := "tjl02sv8fvefol38535m5cguwoHa.966dmn82jcaprs3ulqqtb7v23c"

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
		// TODO: Remove this once we have access to an actual Smartling account and can make direct API calls
		gockSetup func()
	}{
		{
			name: "found, verified",
			s:    Scanner{client: common.SaneHttpClient()},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a smartling userId %s and secret %s within", userId, secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Smartling,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
			// TODO: Remove this once we have access to an actual Smartling account and can make direct API calls
			gockSetup: func() {
				// Expected request body
				body := []byte(fmt.Sprintf(`{"userIdentifier":"%s","userSecret":"%s"}`, userId, secret))

				gock.New("https://api.smartling.com").
					Post("/auth-api/v2/authenticate").
					Body(bytes.NewReader(body)).
					Reply(http.StatusOK).
					JSON(map[string]string{
						"response": "ok",
					})
			},
		},
		{
			name: "found, unverified",
			s:    Scanner{client: common.SaneHttpClient()},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a smartling userId %s and secret %s within but not valid", inactiveUserId, inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Smartling,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
			// TODO: Remove this once we have access to an actual Smartling account and can make direct API calls
			gockSetup: func() {
				// Expected request body
				body := []byte(fmt.Sprintf(`{"userIdentifier":"%s","userSecret":"%s"}`, inactiveUserId, inactiveSecret))

				gock.New("https://api.smartling.com").
					Post("/auth-api/v2/authenticate").
					Body(bytes.NewReader(body)).
					Reply(http.StatusUnauthorized).
					JSON(map[string]string{
						"response": "unauthorized",
					})
			},
		},
		{
			name: "not found",
			s:    Scanner{client: common.SaneHttpClient()},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
			// TODO: Remove this once we have access to an actual Smartling account and can make direct API calls
			gockSetup: func() {},
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a smartling userId %s and secret %s within", userId, secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Smartling,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
			// TODO: Remove this once we have access to an actual Smartling account and can make direct API calls
			gockSetup: func() {},
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a smartling userId %s and secret %s within", userId, secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Smartling,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
			// TODO: Remove this once we have access to an actual Smartling account and can make direct API calls
			gockSetup: func() {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: Remove this once we have access to an actual Smartling account and can make direct API calls
			defer gock.Off()
			defer gock.RestoreClient(tt.s.client)
			gock.InterceptClient(tt.s.client)
			tt.gockSetup()

			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Smartling.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError", "RawV2", "primarySecret")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Smartling.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
