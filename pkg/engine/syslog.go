package engine

import (
	"context"
	"os"

	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/syslog"
)

func (e *Engine) ScanSyslog(ctx context.Context, address, protocol, certPath, keyPath, format string, concurrency int) error {
	connection := &sourcespb.Syslog{
		Protocol:      protocol,
		ListenAddress: address,
		Format:        format,
	}

	if certPath != "" && keyPath != "" {
		cert, err := os.ReadFile(certPath)
		if err != nil {
			return errors.WrapPrefix(err, "could not open TLS cert file", 0)
		}
		connection.TlsCert = string(cert)

		key, err := os.ReadFile(keyPath)
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
	err = source.Init(ctx, "trufflehog - syslog", 0, 0, false, &conn, concurrency)
	source.InjectConnection(connection)
	if err != nil {
		logrus.WithError(err).Error("failed to initialize syslog source")
		return err
	}

	e.sourcesWg.Add(1)
	go func() {
		defer e.sourcesWg.Done()
		err := source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan syslog")
		}
	}()
	return nil
}
