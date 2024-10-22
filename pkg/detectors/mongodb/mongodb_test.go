//go:build detectors
// +build detectors

package mongodb

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

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestMongoDB_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		{
			name:        "long_password",
			data:        `mongodb://agenda-live:m21w7PFfRXQwfHZU1Fgx0rTX29ZBQaWMODLeAjsmyslVcMmcmy6CnLyu3byVDtdLYcCokze8lIE4KyAgSCGZxQ==@agenda-live.mongo.cosmos.azure.com:10255/?retryWrites=false&ssl=true&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@agenda-live@`,
			shouldMatch: true,
		},
		{
			name:        "long_password2",
			data:        `mongodb://csb0230eada-2354-4c73-b3e4-8a1aaa996894:AiNtEyASbdXR5neJmTStMzKGItX2xvKuyEkcy65rviKD0ggZR19E1iVFIJ5ZAIY1xvvAiS5tOXsmACDbKDJIhQ==@csb0230eada-2354-4c73-b3e4-8a1aaa996894.mongo.cosmos.cloud-hostname.com:10255/csb-db0230eada-2354-4c73-b3e4-8a1aaa996894?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@csb0230eada-2354-4c73-b3e4-8a1aaa996894@`,
			shouldMatch: true,
		},
		{
			name:        "long_password3",
			data:        `mongodb://amsdfasfsadfdfdfpshot:6xNRRsdfsdfafd9NodO8vAFFBEHidfdfdfa87QDKXdCMubACDbhfQH1g==@amssdfafdafdadbsnapshot.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@amssadfasdfdbsnsdfadfapshot@`,
			shouldMatch: true,
		},
		{
			name:        "single_host",
			data:        `mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com`,
			shouldMatch: true,
		},
		{
			name:        "single_host+port",
			data:        `mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017`,
			shouldMatch: true,
		},
		{
			name:        "single_host+port+authdb",
			data:        `mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin`,
			shouldMatch: true,
		},
		{
			name:        "single_host_ip",
			data:        `mongodb://myDBReader:D1fficultP%40ssw0rd@192.168.74.143`,
			shouldMatch: true,
		},
		{
			name:        "single_host_ip+port",
			data:        `mongodb://myDBReader:D1fficultP%40ssw0rd@192.168.74.143:27017`,
			shouldMatch: true,
		},
		{
			name:        "multiple_hosts_ip",
			data:        `mongodb://root:root@192.168.74.143:27018,192.168.74.143:27019`,
			shouldMatch: true,
		},
		{
			name:        "multiple_hosts_ip+slash",
			data:        `mongodb://root:root@192.168.74.143:27018,192.168.74.143:27019/`,
			shouldMatch: true,
		},
		{
			name:        "multiple_hosts+port+authdb",
			data:        `mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017,mongodb0.example.com:27017,mongodb0.example.com:27017/?authSource=admin`,
			shouldMatch: true,
		},
		{
			name:        "multiple_hosts+options",
			data:        `mongodb://username:password@mongodb1.example.com:27317,mongodb2.example.com,mongodb2.example.com:270/?connectTimeoutMS=300000&replicaSet=mySet&authSource=aDifferentAuthDB`,
			shouldMatch: true,
		},
		{
			name:        "multiple_hosts2",
			data:        `mongodb://prisma:risima@srv1.bu2lt.mongodb.net:27017,srv2.bu2lt.mongodb.net:27017,srv3.bu2lt.mongodb.net:27017/test?retryWrites=true&w=majority`,
			shouldMatch: true,
		},
		// TODO: These fail because the Go driver doesn't explicitly support `authMechanism=DEFAULT`[1].
		// However, this seems like a valid option[2] and I'm going to try to get that behaviour changed.
		//
		// [1] https://github.com/mongodb/mongo-go-driver/blob/master/x/mongo/driver/connstring/connstring.go#L450-L451
		// [2] https://www.mongodb.com/docs/drivers/node/current/fundamentals/authentication/mechanisms/
		{
			name:        "encoded_options1",
			data:        `mongodb://dave:password@localhost:27017/?authMechanism=DEFAULT&amp;authSource=db&amp;ssl=true&quot;`,
			shouldMatch: true,
			match:       "mongodb://dave:password@localhost:27017/?authMechanism=DEFAULT&authSource=db&ssl=true",
		},
		{
			name:        "encoded_options2",
			data:        `mongodb://cefapp:MdTc8Kc8DzlTE1RUl1JVDGS4zw1U1t6145sPWqeStWA50xEUKPfUCGlnk3ACkfqH6qLAwpnm9awpY1m8dg0YlQ==@cefapp.documents.azure.com:10250/?ssl=true&amp;sslverifycertificate=false`,
			shouldMatch: true,
			match:       "mongodb://cefapp:MdTc8Kc8DzlTE1RUl1JVDGS4zw1U1t6145sPWqeStWA50xEUKPfUCGlnk3ACkfqH6qLAwpnm9awpY1m8dg0YlQ==@cefapp.documents.azure.com:10250/?ssl=true&sslverifycertificate=false",
		},
		{
			name:        "unix_socket",
			data:        `mongodb://u%24ername:pa%24%24w%7B%7Drd@%2Ftmp%2Fmongodb-27017.sock/test`,
			shouldMatch: true,
		},
		{
			name:        "dashes",
			data:        `mongodb://db-user:db-password@mongodb-instance:27017/db-name`,
			shouldMatch: true,
		},
		{
			name: "protocol+srv",
			// TODO: Figure out how to handle `mongodb+srv`. It performs a DNS lookup, which fails if the host doesn't exist.
			//data:        `mongodb+srv://root:randompassword@cluster0.ab1cd.mongodb.net/mydb?retryWrites=true&w=majority`,
			data:        `mongodb://root:randompassword@cluster0.ab1cd.mongodb.net/mydb?retryWrites=true&w=majority`,
			shouldMatch: true,
		},
		{
			name:        "0.0.0.0_host",
			data:        `mongodb://username:password@0.0.0.0:27017/?authSource=admin`,
			shouldMatch: true,
		},
		{
			name:        "localhost_host",
			data:        `mongodb://username:password@localhost:27017/?authSource=admin`,
			shouldMatch: true,
		},
		{
			name:        "127.0.0.1_host",
			data:        `mongodb://username:password@127.0.0.1:27017/?authSource=admin`,
			shouldMatch: true,
		},
		{
			name:        "docker_internal_host",
			data:        `mongodb://username:password@host.docker.internal:27018/?authMechanism=PLAIN&tls=true&tlsCertificateKeyFile=/etc/certs/client.pem&tlsCaFile=/etc/certs/rootCA-cert.pem`,
			shouldMatch: true,
		},
		{
			name:        "options_authsource_external",
			data:        `mongodb://AKIAAAAAAAAAAAA:t9t2mawssecretkey@localhost:27017/?authMechanism=MONGODB-AWS&authsource=$external`,
			shouldMatch: true,
		},
		{
			name:        "generic1",
			data:        `mongodb://root:8b6zfr4b@fastgpt-mongo-mongodb.ns-hti44k5d.svc:27017/`,
			shouldMatch: true,
		},

		// False positives
		{
			name:        "no_password",
			data:        `mongodb://mongodb0.example.com:27017/?replicaSet=myRepl`,
			shouldMatch: false,
		},
		{
			name:        "empty",
			data:        `mongodb://username:@mongodb0.example.com:27017/?replicaSet=myRepl`,
			shouldMatch: false,
		},
		{
			name:        "placeholders_x+single_host",
			data:        `mongodb://xxxx:xxxxx@xxxxxxx:3717/zkquant?replicaSet=mgset-3017917`,
			shouldMatch: false,
		},
		{
			name:        "placeholders_x+multiple_hosts",
			data:        `mongodb://xxxx:xxxxx@xxxxxxx:3717,xxxxxxx:3717/zkquant?replicaSet=mgset-3017917`,
			shouldMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("MongoDB.FromData() error = %v", err)
				return
			}

			if test.shouldMatch {
				if len(results) == 0 {
					t.Errorf("%s: did not receive a match for '%v' when one was expected", test.name, test.data)
					return
				}
				expected := test.data
				if test.match != "" {
					expected = test.match
				}
				result := string(results[0].Raw)
				if result != expected {
					t.Errorf("%s: did not receive expected match.\n\texpected: '%s'\n\t  actual: '%s'", test.name, expected, result)
					return
				}
			} else {
				if len(results) > 0 {
					t.Errorf("%s: received a match for '%v' when one wasn't wanted", test.name, test.data)
					return
				}
			}
		})
	}
}

func TestMongoDB_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("MONGODB_URI")
	inactiveSecret := testSecrets.MustGetField("MONGODB_INACTIVE_URI")

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
				data:   []byte(fmt.Sprintf("You can find a mongodb secret %s within", secret)),
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
				data:   []byte(fmt.Sprintf("You can find a mongodb secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
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
				data:   []byte(fmt.Sprintf("You can find a mongodb secret %s within", secret)),
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
				data:   []byte(fmt.Sprintf("You can find a mongodb secret %s within", strings.ReplaceAll(secret, ".mongodb.net", ".mongodb.net.bad"))),
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
