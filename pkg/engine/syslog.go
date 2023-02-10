package engine

import (
	"os"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
	source := syslog.Source{}
	ctx = context.WithValues(ctx,
		"source_type", source.Type().String(),
		"source_name", "syslog",
	)
	err = source.Init(ctx, "trufflehog - syslog", 0, 0, false, &conn, c.Concurrency)
	source.InjectConnection(connection)
	if err != nil {
		ctx.Logger().Error(err, "failed to initialize syslog source")
		return err
	}

	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			ctx.Logger().Error(err, "could not scan syslog")
		}
	}()
	return nil
}
