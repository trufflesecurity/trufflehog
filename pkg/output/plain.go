package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

var (
	yellowPrinter    = color.New(color.FgYellow)
	greenPrinter     = color.New(color.FgHiGreen)
	boldGreenPrinter = color.New(color.Bold, color.FgHiGreen)
	whitePrinter     = color.New(color.FgWhite)
	boldWhitePrinter = color.New(color.Bold, color.FgWhite)
	cyanPrinter      = color.New(color.FgCyan)
)

// PlainPrinter is a printer that prints results in plain text format.
type PlainPrinter struct {
	mu sync.Mutex
	// Out is where results are written. Defaults to os.Stdout.
	Out io.Writer
	// NoColor disables ANSI colors for this printer only, e.g. when writing to a file.
	NoColor bool
}

// plainWriter writes a result's lines, remembering the first write error so Print can return it.
type plainWriter struct {
	w       io.Writer
	noColor bool
	err     error
}

// printf writes a formatted line in the given color, or uncolored if colors are off.
func (pw *plainWriter) printf(c *color.Color, format string, a ...any) {
	if pw.err != nil {
		return
	}
	if pw.noColor {
		_, pw.err = fmt.Fprintf(pw.w, format, a...)
		return
	}
	_, pw.err = c.Fprintf(pw.w, format, a...)
}

func (p *PlainPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	out := outputFormat{
		DetectorType:        r.DetectorType.String(),
		DecoderType:         r.DecoderType.String(),
		Verified:            r.Verified,
		VerificationError:   r.VerificationError(),
		MetaData:            r.SourceMetadata,
		Raw:                 strings.TrimSpace(string(r.Raw)),
		DetectorDescription: r.DetectorDescription,
	}

	meta, err := structToMap(out.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	printer := greenPrinter
	p.mu.Lock()
	defer p.mu.Unlock()
	// color.Output is stdout, wrapped so ANSI colors also render on Windows consoles
	dst := p.Out
	if dst == nil {
		dst = color.Output
	}
	w := &plainWriter{w: dst, noColor: p.NoColor}

	if out.Verified {
		w.printf(boldGreenPrinter, "✅ Found verified result 🐷🔑\n")
	} else {
		printer = whitePrinter
		w.printf(boldWhitePrinter, "Found unverified result 🐷🔑❓\n")
		if out.VerificationError != nil {
			w.printf(yellowPrinter, "Verification issue: %s\n", out.VerificationError)
		}
	}

	if r.VerificationFromCache {
		w.printf(cyanPrinter, "(🔍 Using cached verification)\n")
	}
	w.printf(printer, "Detector Type: %s\n", out.DetectorType)
	w.printf(printer, "Decoder Type: %s\n", out.DecoderType)
	w.printf(printer, "Raw result: %s\n", p.sprint(whitePrinter, out.Raw))

	for k, v := range r.ExtraData {
		w.printf(
			printer,
			"%s: %v\n",
			cases.Title(language.AmericanEnglish).String(k),
			v)
	}

	if r.StructuredData != nil {
		for idx, v := range r.StructuredData.GithubSshKey {
			w.printf(printer, "GithubSshKey %d User: %s\n", idx, v.User)

			if v.PublicKeyFingerprint != "" {
				w.printf(printer, "GithubSshKey %d Fingerprint: %s\n", idx, v.PublicKeyFingerprint)
			}
		}

		for idx, v := range r.StructuredData.TlsPrivateKey {
			w.printf(printer, "TlsPrivateKey %d Fingerprint: %s\n", idx, v.CertificateFingerprint)
			w.printf(printer, "TlsPrivateKey %d Verification URL: %s\n", idx, v.VerificationUrl)
			w.printf(printer, "TlsPrivateKey %d Expiration: %d\n", idx, v.ExpirationTimestamp)
		}
	}

	aggregateData := make(map[string]any)
	var aggregateDataKeys []string

	for _, data := range meta {
		for k, v := range data {
			aggregateDataKeys = append(aggregateDataKeys, k)
			aggregateData[k] = v
		}
	}
	sort.Strings(aggregateDataKeys)
	for _, k := range aggregateDataKeys {
		w.printf(printer, "%s: %v\n", cases.Title(language.AmericanEnglish).String(k), aggregateData[k])
	}

	// if analysis info is not nil, means the detector added key for analyzer and result is verified
	if r.SecretParts != nil && r.Verified {
		w.printf(printer, "Analyze: Run `trufflehog analyze` to analyze this key's permissions\n")
	}

	w.printf(printer, "\n")
	if w.err != nil {
		return fmt.Errorf("could not write result: %w", w.err)
	}
	return nil
}

// sprint colors a value inline, or returns it as is if the printer has colors off.
func (p *PlainPrinter) sprint(c *color.Color, a ...any) string {
	if p.NoColor {
		return fmt.Sprint(a...)
	}
	return c.Sprint(a...)
}

func structToMap(obj any) (m map[string]map[string]any, err error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &m)
	// Due to PostmanLocationType protobuf field being an enum, we want to be able to assign the string value of the enum to the field without needing to create another Protobuf field.
	// To have the "UNKNOWN_POSTMAN = 0" value be assigned correctly to the field, we need to check if the Postman workspace ID or collection ID is filled since every secret
	// in the Postman source should have a valid workspace ID or collection ID and the 0 value is considered nil for integers.
	if m["Postman"]["workspace_uuid"] != nil || m["Postman"]["collection_id"] != nil {
		if m["Postman"]["location_type"] == nil {
			m["Postman"]["location_type"] = source_metadatapb.PostmanLocationType_UNKNOWN_POSTMAN.String()
		} else {
			m["Postman"]["location_type"] = obj.(*source_metadatapb.MetaData_Postman).Postman.LocationType.String()
		}
	}
	return
}

type outputFormat struct {
	DetectorType,
	DecoderType string
	Verified          bool
	VerificationError error
	Raw               string
	*source_metadatapb.MetaData
	DetectorDescription string
}
