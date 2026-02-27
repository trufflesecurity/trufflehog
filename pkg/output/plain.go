package output

import (
	"encoding/json"
	"fmt"
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
type PlainPrinter struct{ mu sync.Mutex }

func (p *PlainPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	out := outputFormat{
		DetectorType:        r.Result.DetectorType.String(),
		DecoderType:         r.DecoderType.String(),
		Verified:            r.Result.Verified,
		VerificationError:   r.Result.VerificationError(),
		MetaData:            r.SourceMetadata,
		Raw:                 strings.TrimSpace(string(r.Result.Raw)),
		DetectorDescription: r.DetectorDescription,
	}

	meta, err := structToMap(out.MetaData.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	printer := greenPrinter
	p.mu.Lock()
	defer p.mu.Unlock()

	if out.Verified {
		boldGreenPrinter.Print("✅ Found verified result 🐷🔑\n")
	} else {
		printer = whitePrinter
		boldWhitePrinter.Print("Found unverified result 🐷🔑❓\n")
		if out.VerificationError != nil {
			yellowPrinter.Printf("Verification issue: %s\n", out.VerificationError)
		}
	}

	if r.VerificationFromCache {
		cyanPrinter.Print("(🔍 Using cached verification)\n")
	}

	printer.Printf("Detector Type: %s\n", out.DetectorType)
	printer.Printf("Decoder Type: %s\n", out.DecoderType)
	printer.Printf("Raw result: %s\n", whitePrinter.Sprint(out.Raw))

	for k, v := range r.Result.ExtraData {
		printer.Printf(
			"%s: %v\n",
			cases.Title(language.AmericanEnglish).String(k),
			v)
	}

	if r.Result.StructuredData != nil {
		for idx, v := range r.Result.StructuredData.GithubSshKey {
			printer.Printf("GithubSshKey %d User: %s\n", idx, v.User)

			if v.PublicKeyFingerprint != "" {
				printer.Printf("GithubSshKey %d Fingerprint: %s\n", idx, v.PublicKeyFingerprint)
			}
		}

		for idx, v := range r.Result.StructuredData.TlsPrivateKey {
			printer.Printf("TlsPrivateKey %d Fingerprint: %s\n", idx, v.CertificateFingerprint)
			printer.Printf("TlsPrivateKey %d Verification URL: %s\n", idx, v.VerificationUrl)
			printer.Printf("TlsPrivateKey %d Expiration: %d\n", idx, v.ExpirationTimestamp)
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
		printer.Printf("%s: %v\n", cases.Title(language.AmericanEnglish).String(k), aggregateData[k])
	}

	// if analysis info is not nil, means the detector added key for analyzer and result is verified
	if r.Result.AnalysisInfo != nil && r.Result.Verified {
		printer.Printf("Analyze: Run `trufflehog analyze` to analyze this key's permissions\n")
	}

	fmt.Println("")
	return nil
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
