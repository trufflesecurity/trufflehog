package syslog

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_parseSyslogMetadata(t *testing.T) {
	type args struct {
		format string
		input  []byte
		remote string
	}
	tests := []struct {
		name    string
		args    args
		want    *source_metadatapb.MetaData
		wantErr bool
	}{
		{
			name: "success - rfc5424",
			args: args{
				format: "rfc5424",
				input:  []byte("<14>1 2025-08-05T12:00:00Z my-host my-app 1234 ID47 - Test message"),
				remote: "127.0.0.1:5140",
			},
			want: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Syslog{
					Syslog: &source_metadatapb.Syslog{
						Hostname:  "my-host",
						Appname:   "my-app",
						Procid:    "1234",
						Timestamp: "2025-08-05 12:00:00 +0000 UTC",
						Client:    "127.0.0.1:5140",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "success - rfc5424",
			args: args{
				format: "rfc5424",
				input:  []byte("<34>1 2023-08-05T14:30:22.123Z webserver nginx 1234 access-log - 192.168.1.100 GET /index.html 200"),
				remote: "127.0.0.1:5140",
			},
			want: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Syslog{
					Syslog: &source_metadatapb.Syslog{
						Hostname:  "webserver",
						Appname:   "nginx",
						Procid:    "1234",
						Timestamp: "2023-08-05 14:30:22.123 +0000 UTC",
						Client:    "127.0.0.1:5140",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "success - rfc3164",
			args: args{
				format: "rfc3164",
				input:  []byte("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"),
				remote: "127.0.0.1:5140",
			},
			want: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Syslog{
					Syslog: &source_metadatapb.Syslog{
						Hostname: "mymachine",
						Timestamp: time.Date(
							time.Now().Year(),
							time.October,
							11,
							22, 14, 15,
							0,
							time.UTC,
						).String(),
						Client:   "127.0.0.1:5140",
						Facility: "4",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "fail - wrong format",
			args: args{
				format: "rfc5424",
				input:  []byte("Test message"),
				remote: "127.0.0.1:5140",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{}

			conn, err := anypb.New(&sourcespb.Syslog{
				Format: tt.args.format,
			})
			assert.NoError(t, err)

			err = s.Init(context.Background(), "test", 0, 0, false, conn, 5)
			assert.NoError(t, err)

			got, err := s.parseSyslogMetadata(tt.args.input, tt.args.remote)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.parseSyslogMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Source.parseSyslogMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSource_DebugLogging(t *testing.T) {
	const testSecret = "syslogdebuglogtestsecret"
	message := "<165>1 2003-10-11T22:14:15.003Z host app - ID47 - password=" + testSecret

	runSource := func(t *testing.T, debug bool) []observer.LoggedEntry {
		t.Helper()
		ctx, logs := logtest.SourceContext(debug)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Find a free port for the listener.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := l.Addr().String()
		require.NoError(t, l.Close())

		s := &Source{}
		conn, err := anypb.New(&sourcespb.Syslog{Protocol: "tcp", ListenAddress: addr, Format: "rfc5424"})
		require.NoError(t, err)
		require.NoError(t, s.Init(ctx, "test source", 1, 1, false, conn, 1))
		if debug {
			logtest.CheckInitLine(t, logs.All())
		}

		chunksChan := make(chan *sources.Chunk, 2)
		done := make(chan error, 1)
		go func() { done <- s.Chunks(ctx, chunksChan) }()

		var client net.Conn
		require.Eventually(t, func() bool {
			client, err = net.Dial("tcp", addr)
			return err == nil
		}, 5*time.Second, 10*time.Millisecond)

		// One good message, then one that does not parse, which is still scanned.
		for _, msg := range []string{message, "not a syslog message"} {
			_, err = client.Write([]byte(msg))
			require.NoError(t, err)
			chunk := <-chunksChan
			assert.Equal(t, msg, string(chunk.Data), "chunk holds only the bytes read")
		}
		require.NoError(t, client.Close())

		// Cancel stops the scan even though Accept is waiting for a client.
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("Chunks did not return after cancel")
		}
		return logs.All()
	}

	t.Run("debug on", func(t *testing.T) {
		logtest.CheckSourceLines(t, runSource(t, true), testSecret)
	})

	t.Run("debug off", func(t *testing.T) {
		logtest.CheckNoDebugLines(t, runSource(t, false))
	})
}
