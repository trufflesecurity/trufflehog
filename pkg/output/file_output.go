package output

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// Output formats accepted by --output.
const (
	FormatPlain         = "plain"
	FormatJSON          = "json"
	FormatLegacyJSON    = "json-legacy"
	FormatGitHubActions = "github-actions"
	FormatSARIF         = "sarif"
)

// Formats lists the formats accepted by --output, in the order they're shown in help text.
var Formats = []string{FormatPlain, FormatJSON, FormatLegacyJSON, FormatGitHubActions, FormatSARIF}

// ResultPrinter is the same as engine.Printer, which this package can't import (engine imports output).
type ResultPrinter interface {
	Print(ctx context.Context, r *detectors.ResultWithMetadata) error
}

// writerOrStdout returns w, or os.Stdout if w is nil, so a zero-value printer keeps printing to stdout.
func writerOrStdout(w io.Writer) io.Writer {
	if w == nil {
		return os.Stdout
	}
	return w
}

// MultiPrinter sends every result to each of its printers, so a single scan can produce several
// outputs (e.g. human-readable on stdout and JSON in a file).
type MultiPrinter struct {
	printers []ResultPrinter
}

// NewMultiPrinter returns a printer that prints each result with every one of printers, in order.
func NewMultiPrinter(printers ...ResultPrinter) *MultiPrinter {
	return &MultiPrinter{printers: printers}
}

// Print prints r with every printer. A failing printer doesn't stop the others; their errors are joined.
func (m *MultiPrinter) Print(ctx context.Context, r *detectors.ResultWithMetadata) error {
	var errs []error
	for _, p := range m.printers {
		if err := p.Print(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FileOutputSpec is a parsed --output value: write results in Format to the file at Path.
type FileOutputSpec struct {
	Format string
	Path   string
}

// ParseFileOutputSpec parses a --output value of the form FORMAT:PATH, e.g. "json:results.json".
// Only the first colon separates the two, so Windows paths such as "json:C:\out.json" work.
func ParseFileOutputSpec(value string) (FileOutputSpec, error) {
	format, path, found := strings.Cut(value, ":")
	format = strings.ToLower(strings.TrimSpace(format))
	if !found || format == "" || strings.TrimSpace(path) == "" {
		return FileOutputSpec{}, fmt.Errorf("invalid output %q: expected FORMAT:PATH, e.g. json:results.json", value)
	}
	if !isKnownFormat(format) {
		return FileOutputSpec{}, fmt.Errorf("invalid output %q: unknown format %q (expected one of %s)", value, format, strings.Join(Formats, ", "))
	}
	return FileOutputSpec{Format: format, Path: path}, nil
}

func isKnownFormat(format string) bool {
	for _, f := range Formats {
		if f == format {
			return true
		}
	}
	return false
}

// FileOutput is a printer writing one format to one file. Close must be called once the scan has
// finished: it writes buffered formats (SARIF) and closes the file.
type FileOutput struct {
	Spec    FileOutputSpec
	printer ResultPrinter
	file    *os.File
}

// Print writes r to the file.
func (o *FileOutput) Print(ctx context.Context, r *detectors.ResultWithMetadata) error {
	if err := o.printer.Print(ctx, r); err != nil {
		return fmt.Errorf("%s output %s: %w", o.Spec.Format, o.Spec.Path, err)
	}
	return nil
}

// Close flushes anything the format buffers until the end of the scan, then closes the file.
func (o *FileOutput) Close() error {
	var flushErr error
	if sarif, ok := o.printer.(*SarifPrinter); ok {
		flushErr = sarif.Flush(o.file)
	}
	return errors.Join(flushErr, o.file.Close())
}

// OpenFileOutputs parses each --output value and creates (or truncates) its file. Files are created
// with 0600 permissions because results contain raw secrets. If any value is invalid or any file
// can't be created, files opened so far are closed and an error is returned.
func OpenFileOutputs(values []string) ([]*FileOutput, error) {
	outputs := make([]*FileOutput, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	closeAll := func() {
		for _, o := range outputs {
			_ = o.file.Close()
		}
	}

	for _, value := range values {
		spec, err := ParseFileOutputSpec(value)
		if err != nil {
			closeAll()
			return nil, err
		}
		if _, dup := seen[spec.Path]; dup {
			closeAll()
			return nil, fmt.Errorf("invalid output %q: %s is already used by another --output", value, spec.Path)
		}
		seen[spec.Path] = struct{}{}

		file, err := os.OpenFile(spec.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("could not open output file: %w", err)
		}
		// the mode above only applies to new files; tighten an existing one before writing secrets to it
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			closeAll()
			return nil, fmt.Errorf("could not restrict permissions on output file %s: %w", spec.Path, err)
		}
		outputs = append(outputs, &FileOutput{Spec: spec, printer: newPrinter(spec.Format, file), file: file})
	}
	return outputs, nil
}

// newPrinter returns a printer for format that writes to w. Plain text is written without colors,
// since ANSI escape codes only make sense on a terminal.
func newPrinter(format string, w io.Writer) ResultPrinter {
	switch format {
	case FormatJSON:
		return &JSONPrinter{Out: w}
	case FormatLegacyJSON:
		return &LegacyJSONPrinter{Out: w}
	case FormatGitHubActions:
		return &GitHubActionsPrinter{Out: w}
	case FormatSARIF:
		return &SarifPrinter{}
	default:
		return &PlainPrinter{Out: w, NoColor: true}
	}
}
