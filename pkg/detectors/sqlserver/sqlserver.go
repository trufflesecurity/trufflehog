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

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

type Scanner struct {
	ignorePatterns []*regexp.Regexp
}

func New(opts ...func(*Scanner)) *Scanner {
	scanner := &Scanner{
		ignorePatterns: []*regexp.Regexp{},
	}
	for _, opt := range opts {
		opt(scanner)
	}

	return scanner
}

func WithIgnorePattern(ignoreStrings []string) func(*Scanner) {
	return func(s *Scanner) {
		var ignorePatterns []*regexp.Regexp
		for _, ignoreString := range ignoreStrings {
			ignorePattern, err := regexp.Compile(ignoreString)
			if err != nil {
				panic(fmt.Sprintf("%s is not a valid regex, error received: %v", ignoreString, err))
			}
			ignorePatterns = append(ignorePatterns, ignorePattern)
		}

		s.ignorePatterns = ignorePatterns
	}
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// SQLServer connection string is a semicolon delimited set of case-insensitive parameters which may go in any order.
	// Values may contain $, backticks, and apostrophes: those characters are
	// valid inside real passwords (see #5501), so only the pair separator (;)
	// and the double-quote wrapper terminate a value. Whole-placeholder
	// passwords are filtered out separately by isPlaceholderPassword.
	pattern = regexp.MustCompile("(?:\n|`|'|\"| )?((?:[A-Za-z0-9_ ]+=[^;\"]+;?){3,})(?:'|`|\"|\r\n|\n)?")

	// placeholderPasswordPattern matches a password that is a whole template
	// placeholder rather than a real credential: $(Name), ${NAME}, an
	// all-caps $ENV_VAR reference, or a {Token} format-string token (see
	// #5192). It is anchored to the whole password, so a password that merely
	// contains placeholder-like syntax (e.g. Ab$cd, $cdFakeOnly123, or
	// Pass{0}word) is still reported. A bare $identifier is only treated as a
	// placeholder when it looks like an environment-variable reference
	// (all-caps); a mixed-case value such as $cdFakeOnly123 is
	// indistinguishable from a real password and is reported.
	placeholderPasswordPattern = regexp.MustCompile(`^(\$\([^)]*\)|\$\{[^}]*\}|\$[A-Z][A-Z0-9_]*|\{[^}]*\})$`)
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
		if shouldIgnore(match[1], s.ignorePatterns) {
			continue
		}
		params := match[1]
		// The greedy value class terminates only on ';' and '"', so when a
		// connection string is wrapped in ' or ` and the final field has no
		// trailing semicolon, the closing wrapper is absorbed into that
		// field's value (e.g. Password=abc' yields Raw "abc'"). Strip at
		// most one trailing wrapper char, and only when the overall match
		// opened with that same wrapper: an unquoted value that genuinely
		// ends in ' or ` (see #5501) is left untouched.
		if len(match[0]) > 0 && len(params) > 0 {
			if wrapper := match[0][0]; wrapper == '\'' || wrapper == '`' {
				if params[len(params)-1] == wrapper {
					params = params[:len(params)-1]
				}
			}
		}
		paramsUnsafe, err := msdsn.Parse(params)
		if err != nil {
			continue
		}

		if paramsUnsafe.Password == "" {
			continue
		}

		if isPlaceholderPassword(paramsUnsafe.Password) {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_SQLServer,
			Raw:          []byte(paramsUnsafe.Password),
			RawV2:        []byte(paramsUnsafe.URL().String()),
			SecretParts: map[string]string{
				"host":     paramsUnsafe.Host,
				"database": paramsUnsafe.Database,
				"user":     paramsUnsafe.User,
				"password": paramsUnsafe.Password,
			},
			Redacted: detectors.RedactURL(*paramsUnsafe.URL()),
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

// isPlaceholderPassword reports whether a parsed password is a whole
// template placeholder (see placeholderPasswordPattern) rather than a
// real credential.
func isPlaceholderPassword(password string) bool {
	return placeholderPasswordPattern.MatchString(password)
}

func shouldIgnore(uri string, ignorePatterns []*regexp.Regexp) bool {
	for _, ignore := range ignorePatterns {
		if ignore.MatchString(uri) {
			return true
		}
	}
	return false
}

const defaultSQLServerPort = 1433

// preDialAddress returns the host:port the driver will dial, or false when the
// port is resolved through SQL Browser and can't be checked ahead of time.
func preDialAddress(config msdsn.Config) (string, bool) {
	port := config.Port
	if port == 0 {
		if config.Instance != "" {
			return "", false
		}
		port = defaultSQLServerPort
	}
	return net.JoinHostPort(config.Host, strconv.Itoa(int(port))), true
}

var ping = func(ctx context.Context, config msdsn.Config) (bool, error) {
	// TCP connectivity check to prevent indefinite hangs
	if address, ok := preDialAddress(config); ok {
		dialer := &net.Dialer{
			Timeout: 3 * time.Second,
		}

		tcpConn, err := dialer.DialContext(ctx, "tcp", address) // respects context timeout
		if err != nil {
			return false, err
		}
		defer func() { _ = tcpConn.Close() }()
	}

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

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SQLServer
}

func (s Scanner) Description() string {
	return "SQL Server is a relational database management system developed by Microsoft. SQL Server credentials can be used to access and manage databases."
}
