package engine

import (
	"os"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/syslog"
)

// ScanSyslog is a source that scans syslog files.
func (e *Engine) ScanSyslog(ctx context.Context, c sources.SyslogConfig) error {
	connection := &sourcespb.Syslog{
		Protocol:      c.Protocol,
		ListenAddress: c.Address,
		Format:        c.Format,
	}

	if c.CertPath != "" && c.KeyPath != "" {
		cert, err := os.ReadFile(c.CertPath)
		if err != nil {
			return errors.WrapPrefix(err, "could not open TLS cert file", 0)
		}
		connection.TlsCert = string(cert)

		key, err := os.ReadFile(c.KeyPath)
		if err != nil {
			return errors.WrapPrefix(err, "could not open TLS key file", 0)
		}
		connection.TlsKey = string(key)
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	handle, err := e.sourceManager.Enroll(ctx, "trufflehog - syslog", new(syslog.Source).Type(),
		func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
			syslogSource := syslog.Source{}
			if err := syslogSource.Init(ctx, "trufflehog - syslog", jobID, sourceID, true, &conn, c.Concurrency); err != nil {
				return nil, err
			}
			syslogSource.InjectConnection(connection)
			return &syslogSource, nil
		})
	if err != nil {
		return err
	}
	_, err = e.sourceManager.ScheduleRun(ctx, handle)
	return err
}
