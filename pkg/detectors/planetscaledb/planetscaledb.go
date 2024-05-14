package planetscaledb

import (
	"context"
	"database/sql"
	regexp "github.com/wasilibs/go-re2"
	"strings"

	"github.com/go-sql-driver/mysql"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	usernamePat = regexp.MustCompile(`\b[a-z0-9]{20}\b`)
	passwordPat = regexp.MustCompile(`\bpscale_pw_[A-Za-z0-9_]{43}\b`)
	hostPat     = regexp.MustCompile(`\b(aws|gcp)\.connect\.psdb\.cloud\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"pscale_pw_"}
}

// FromData will find and optionally verify Planetscaledb secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	usernameMatches := usernamePat.FindAllStringSubmatch(dataStr, -1)
	passwordMatches := passwordPat.FindAllStringSubmatch(dataStr, -1)
	hostMatches := hostPat.FindAllString(dataStr, -1)

	for _, username := range usernameMatches {
		for _, password := range passwordMatches {
			for _, host := range hostMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_PlanetScaleDb,
					Raw:          []byte(strings.Join([]string{host, username[0], password[0]}, "\t")),
				}

				if verify {
					cfg := mysql.Config{
						User:                 username[0],
						Passwd:               password[0],
						Net:                  "tcp",
						Addr:                 host,
						TLSConfig:            "true", // assuming SSL is required
						AllowNativePasswords: true,
					}
					db, err := sql.Open("mysql", cfg.FormatDSN())
					if err != nil {
						s1.SetVerificationError(err, password[0])
					} else {
						err = db.PingContext(ctx)
						if err == nil {
							s1.Verified = true
						} else {
							s1.SetVerificationError(err, password[0])
						}
						db.Close()
					}
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PlanetScaleDb
}
