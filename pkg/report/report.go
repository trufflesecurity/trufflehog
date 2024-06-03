package report

import (
	"encoding/json"
	"io"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type jobReporter struct {
	*UnitHook
}

type jobReporterOpt func(*jobReporter)

func New(opts ...jobReporterOpt) jobReporter {
	j := jobReporter{UnitHook: NewUnitHook()}
	for _, opt := range opts {
		opt(&j)
	}
	return j
}

func WithWriter(ctx context.Context, w io.WriteCloser) jobReporterOpt {
	return func(reporter *jobReporter) {
		OnFinishedMetric(func(metrics UnitMetrics) {
			metrics.Errors = common.ExportErrors(metrics.Errors...)
			details, err := json.Marshal(map[string]any{
				"version": 1,
				"data":    metrics,
			})
			if err != nil {
				ctx.Logger().Error(err, "error marshalling job details")
				return
			}
			if _, err := w.Write(append(details, '\n')); err != nil {
				ctx.Logger().Error(err, "error writing to file")
			}
		})(reporter.UnitHook)
		OnClose(func() {
			w.Close()
			// Add a bit of extra information if it's a *os.File.
			if namer, ok := w.(interface{ Name() string }); ok {
				ctx.Logger().Info("report written", "path", namer.Name())
			} else {
				ctx.Logger().Info("report written")
			}
		})(reporter.UnitHook)
	}
}
