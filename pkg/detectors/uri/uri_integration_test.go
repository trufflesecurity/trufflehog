//go:build detectors
// +build detectors

package uri

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestURI_FromChunk(t *testing.T) {
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
			name: "found, unverified, wrong username",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a uri secret %s within", "https://user:pass@httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx")),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_URI,
					Verified:     false,
					Redacted:     "https://user:********@httpwatch.com",
				},
			},
			wantErr: false,
		},
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a uri secret %s within", "https://httpwatch:pass@www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx")),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_URI,
					Verified:     true,
					Redacted:     "https://httpwatch:********@www.httpwatch.com",
				},
			},
			wantErr: false,
		},
		{
			name: "found, verified, defused",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a uri secret %s within", "https://httpwatch:pass@www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx?foo=bar")),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_URI,
					Verified:     true,
					Redacted:     "https://httpwatch:********@www.httpwatch.com",
				},
			},
			wantErr: false,
		},
		{
			name: "found, verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a uri secret %s within", "https://httpwatch:pass@www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx")),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_URI,
					Verified:     false,
					Redacted:     "https://httpwatch:********@www.httpwatch.com",
				}
				r.SetVerificationError(fmt.Errorf("context deadline exceeded"))
				return []detectors.Result{r}
			}(),
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "bad scheme",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("file://user:pass@foo.com:123/wh/at/ever"),
				verify: true,
			},
			wantErr: false,
		},
		{
			name: "nothing found, password was redacted two different ways",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("Both %s and %s have been redacted within", "https://httpwatch::********@www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx?foo=bar", "https://httpwatch::%2A%2A%2A%2A%2A%2A@www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx?foo=bar")),
				verify: true,
			},
			want:    []detectors.Result{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.allowKnownTestSites = true
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("URI.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if os.Getenv("FORCE_PASS_DIFF") == "true" {
			// 	return
			// }
			for i := range got {
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Errorf("URI.FromData() error = %v, wantVerificationErr %v", got[i].VerificationError(), tt.want[i])
					return
				}
				got[i].Raw = nil
				got[i].RawV2 = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("URI.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
