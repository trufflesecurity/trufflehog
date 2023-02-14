package sqlserver

import (
	"context"
	"database/sql"
	"regexp"

	"github.com/denisenkom/go-mssqldb/msdsn"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// SQLServer connection string is a semicolon delimited set of case-insensitive parameters which may go in any order.
	pattern = regexp.MustCompile("(?:\n|`|'|\"| )?((?:[A-Za-z0-9_ ]+=[^;$'`\"$]+;?){3,})(?:'|`|\"|\r\n|\n)?")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sqlserver"}
}

// FromData will find and optionally verify SpotifyKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := pattern.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		params, _, err := msdsn.Parse(match[1])
		if err != nil {
			continue
		}

		if params.Password == "" {
			continue
		}

		detected := detectors.Result{
			DetectorType: detectorspb.DetectorType_SQLServer,
			Raw:          []byte(params.Password),
		}

		if verify {
			verified, err := ping(params)
			if err != nil {
			} else {
				detected.Verified = verified
			}
		}

		results = append(results, detected)
	}

	return results, nil
}

var ping = func(config msdsn.Config) (bool, error) {
	url := config.URL()
	query := url.Query()
	query.Set("dial timeout", "3")
	query.Set("connection timeout", "3")
	url.RawQuery = query.Encode()

	conn, err := sql.Open("mssql", url.String())
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	err = conn.Ping()
	if err != nil {
		return false, err
	}

	return true, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SQLServer
}
