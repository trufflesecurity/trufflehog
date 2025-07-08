package sqlserver

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"time"

	regexp "github.com/wasilibs/go-re2"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

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
	return []string{"sql", "database", "Data Source", "Server=", "Network address="}
}

// FromData will find and optionally verify SQL Server credentials in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := pattern.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		paramsUnsafe, err := msdsn.Parse(match[1])
		if err != nil {
			continue
		}

		if paramsUnsafe.Password == "" {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SQLServer,
			Raw:          []byte(paramsUnsafe.Password),
			RawV2:        []byte(paramsUnsafe.URL().String()),
			Redacted:     detectors.RedactURL(*paramsUnsafe.URL()),
		}

		if verify {
			isVerified, err := ping(ctx, paramsUnsafe)

			s1.Verified = isVerified
			mssqlErr, isMssqlErr := err.(mssql.Error)
			if isMssqlErr {
				if mssqlErr.Number == 18456 {
					// Login failed
					// Number taken from https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors?view=sql-server-ver16
					// Nothing to do; determinate failure to verify
				} else {
					// If it is a MSSQL error, format the error with error number and message
					s1.SetVerificationError(fmt.Errorf("SQL Server error %d: %s", mssqlErr.Number, mssqlErr.Message), paramsUnsafe.Password)
				}
			} else if err != nil {
				// If it is an error but not of MSSQL error type, just set error as verification error
				s1.SetVerificationError(err, paramsUnsafe.Password)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

var ping = func(ctx context.Context, config msdsn.Config) (bool, error) {
	// TCP connectivity check to prevent indefinite hangs
	address := net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port)))

	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}

	tcpConn, err := dialer.DialContext(ctx, "tcp", address) // respects context timeout
	if err != nil {
		return false, err
	}
	defer tcpConn.Close()

	cleanConfig := msdsn.Config{}
	cleanConfig.Host = config.Host
	cleanConfig.Port = config.Port
	cleanConfig.User = config.User
	cleanConfig.Password = config.Password
	cleanConfig.Database = config.Database
	cleanConfig.DisableRetry = true
	cleanConfig.Encryption = config.Encryption
	cleanConfig.TLSConfig = config.TLSConfig
	cleanConfig.Instance = config.Instance
	cleanConfig.DialTimeout = time.Second * 3
	cleanConfig.ConnTimeout = time.Second * 3

	url := cleanConfig.URL()
	query := url.Query()
	url.RawQuery = query.Encode()

	conn, err := sql.Open("mssql", url.String())
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	err = conn.PingContext(ctx) // this doesn't seem to respect the context timeout
	if err != nil {
		return false, err
	}

	return true, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SQLServer
}

func (s Scanner) Description() string {
	return "SQL Server is a relational database management system developed by Microsoft. SQL Server credentials can be used to access and manage databases."
}
