//go:build detectors && integration
// +build detectors,integration

package mongodb

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestIntegrationMongoDB_FromChunk(t *testing.T) {

	ctx := context.Background()

	mongoDbUser := gofakeit.Username()
	mongoDbPass := gofakeit.Password(true, true, true, false, false, 10)

	mongoContainer, err := mongodb.RunContainer(
		ctx,
		testcontainers.WithImage("mongo:7.0.11"),
		mongodb.WithUsername(mongoDbUser),
		mongodb.WithPassword(mongoDbPass),
		testcontainers.WithWaitStrategy(
			// mongodb logs "Waiting for connections" twice after that it starts accepting connections
			wait.ForLog("Waiting for connections").WithOccurrence(2).WithStartupTimeout(10*time.Second),
		),
	)

	if err != nil {
		t.Fatal(err)
	}
	defer mongoContainer.Terminate(ctx)

	port, err := mongoContainer.MappedPort(ctx, "27017")
	if err != nil {
		t.Fatal(err)
	}
	host, err := mongoContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// mongodb+srv://mongotester:Risa0y3t35Si1qT3@cluster0.z8js2ni.mongodb.net/?retryWrites=true&w=majority
	// mongodb+srv://mongotester:risa0y3t35Si1qT3@cluster0.z8js2ni.mongodb.net/?retryWrites=true&w=majority

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
				data:   []byte(fmt.Sprintf("mongodb://%s:%s@%s:%s/?retryWrites=true&w=majority", mongoDbUser, mongoDbPass, host, port.Port())),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_MongoDB,
					Verified:     true,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/mongo/",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("mongodb://%s:%s@%s:%s/?retryWrites=true&w=majority", mongoDbUser, "invalidPassword", host, port)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_MongoDB,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/mongo/",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, would be verified but for connection timeout",
			s:    Scanner{timeout: 1 * time.Microsecond},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("mongodb://%s:%s@%s:%s/?retryWrites=true&w=majority", mongoDbUser, mongoDbPass, host, port.Port())),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_MongoDB,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/mongo/",
					},
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, bad host",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("mongodb://%s:%s@%s:%s/?retryWrites=true&w=majority", mongoDbUser, mongoDbPass, "bad.host", port.Port())),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_MongoDB,
					Verified:     false,
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/mongo/",
					},
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
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
				t.Errorf("MongoDB.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationErr = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "RawV2", "verificationError")
			if diff := cmp.Diff(tt.want, got, ignoreOpts); diff != "" {
				t.Errorf("MongoDB.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
