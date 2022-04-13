package engine

import (
	"context"
	"os"

	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/syslog"
)

func (e *Engine) ScanSyslog(ctx context.Context, address, protocol, certPath, keyPath, format string, concurrency int) error {
	conn := &sourcespb.Syslog{
		Protocol:      protocol,
		ListenAddress: address,
		Format:        format,
	}

	if certPath != "" && keyPath != "" {
		cert, err := os.ReadFile(certPath)
		if err != nil {
			return errors.WrapPrefix(err, "could not open TLS cert file", 0)
		}
		conn.TlsCert = string(cert)

		key, err := os.ReadFile(keyPath)
		if err != nil {
			return errors.WrapPrefix(err, "could not open TLS key file", 0)
		}
		conn.TlsKey = string(key)
	}

	source := syslog.Source{}
	err := source.Init(ctx, "trufflehog - syslog", 0, 0, false, nil, concurrency)
	source.InjectConnection(conn)
	if err != nil {
		logrus.WithError(err).Error("failed to initialize syslog source")
		return err
	}

	go func() {
		err := source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan syslog")
		}
		close(e.ChunksChan())
	}()
	return nil
}
