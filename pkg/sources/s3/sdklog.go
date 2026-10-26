package s3

import (
	stdctx "context"
	"fmt"

	"github.com/aws/smithy-go/logging"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// sdkLogger passes the AWS SDK's retry logs to the logger of the request's
// context, so they carry that request's fields and follow per-source debug.
// The zero value is what the client holds. It drops anything logged without a
// request context, since there is no logger to send it to.
type sdkLogger struct {
	ctx stdctx.Context
}

var _ logging.ContextLogger = sdkLogger{}

func (l sdkLogger) WithContext(ctx stdctx.Context) logging.Logger {
	return sdkLogger{ctx: ctx}
}

func (l sdkLogger) Logf(_ logging.Classification, format string, v ...any) {
	if l.ctx == nil {
		return
	}
	logger := context.AddLogger(l.ctx).Logger().V(4)
	if logger.Enabled() {
		logger.Info("AWS SDK", "detail", fmt.Sprintf(format, v...))
	}
}
