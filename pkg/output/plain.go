package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

var (
	yellowPrinter = color.New(color.FgYellow)
	greenPrinter  = color.New(color.FgHiGreen)
	whitePrinter  = color.New(color.FgWhite)
)

func PrintPlainOutput(r *detectors.ResultWithMetadata) {
	out := outputFormat{
		DetectorType: r.Result.DetectorType.String(),
		Verified:     r.Result.Verified,
		MetaData:     r.SourceMetadata,
		Raw:          strings.TrimSpace(string(r.Result.Raw)),
	}

	meta, err := structToMap(out.MetaData.Data)
	if err != nil {
		logrus.WithError(err).Fatal("could not marshal result")
	}

	printer := greenPrinter

	if out.Verified {
		yellowPrinter.Print("Found verified result 🐷🔑\n")
	} else {
		printer = whitePrinter
		whitePrinter.Print("Found unverified result 🐷🔑❓\n")
	}
	printer.Printf("Detector Type: %s\n", out.DetectorType)
	printer.Printf("Raw result: %s\n", whitePrinter.Sprint(out.Raw))
	for _, data := range meta {
		for k, v := range data {
			printer.Printf("%s: %v\n", strings.Title(k), v)
		}
	}
	fmt.Println("")
}

func structToMap(obj interface{}) (m map[string]map[string]interface{}, err error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &m)
	return
}

type outputFormat struct {
	DetectorType string
	Verified     bool
	Raw          string
	*source_metadatapb.MetaData
}
