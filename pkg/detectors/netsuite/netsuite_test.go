//go:build detectors
// +build detectors

package netsuite

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestNetsuite_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	consumerKey := testSecrets.MustGetField("NETSUITE_CONSUMER_KEY")
	consumerSecret := testSecrets.MustGetField("NETSUITE_CONSUMER_SECRET")
	tokenKey := testSecrets.MustGetField("NETSUITE_TOKEN_KEY")
	tokenSecret := testSecrets.MustGetField("NETSUITE_TOKEN_SECRET")
	accountID := testSecrets.MustGetField("NETSUITE_ACCOUNT_ID")

	inactiveConsumerSecret := testSecrets.MustGetField("NETSUITE_CONSUMER_SECRET_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name               string
		s                  Scanner
		args               args
		wantCount          int
		wantErr            bool
		ShouldHaveVerified bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`netsuite credentials
					 consumer key %s 
					 consumer secret %s, 
					 token key %s, 
					 token secret %s, 
					 account id %s`,
					consumerKey,
					consumerSecret,
					tokenKey,
					tokenSecret,
					accountID)),
				verify: true,
			},
			ShouldHaveVerified: true,
			wantCount:          1,
			wantErr:            false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf("You can find a netsuite consumer key %s but not valid with secret %s, token key %s, token secret %s, account id %s",
					consumerKey,
					inactiveConsumerSecret,
					tokenKey,
					tokenSecret,
					accountID)),
				verify: true,
			},
			ShouldHaveVerified: false,
			wantCount:          21,
			wantErr:            false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			ShouldHaveVerified: false,
			wantCount:          0,
			wantErr:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Netsuite.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.ShouldHaveVerified {
				var verifiedResults []detectors.Result
				// filter verified results
				for i := range got {
					if got[i].Verified {
						verifiedResults = append(verifiedResults, got[i])
					}
				}

				if len(verifiedResults) != tt.wantCount {
					t.Errorf("Netsuite.FromData() got = %v, want %v", len(verifiedResults), tt.wantCount)
				}
			} else {
				if len(got) != tt.wantCount {
					t.Errorf("Netsuite.FromData() got = %v, want %v", len(got), tt.wantCount)
				}
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
