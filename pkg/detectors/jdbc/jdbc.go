package jdbc

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`(?i)jdbc:[\w]{3,10}:[^\s"']{0,512}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"jdbc"}
}

// FromData will find and optionally verify Jdbc secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		jdbcConn := match[0]

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_JDBC,
			Raw:          []byte(jdbcConn),
			Redacted:     tryRedactAnonymousJDBC(jdbcConn),
		}

		if verify {
			s.Verified = false
			j, err := newJDBC(jdbcConn)
			if err != nil {
				continue
			}
			s.Verified = j.ping()
			// TODO: specialized redaction
		}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s)
	}

	return
}

func tryRedactAnonymousJDBC(conn string) string {
	userPass, postfix, found := strings.Cut(conn, "@")
	if found {
		if index := strings.LastIndex(userPass, ":"); index != -1 {
			prefix, pass := userPass[:index], userPass[index+1:]
			return prefix + ":" + strings.Repeat("*", len(pass)) + "@" + postfix
		}
	}
	prefix, paramString, found := strings.Cut(conn, "?")
	if !found {
		return conn
	}
	var newParams []string
	for _, param := range strings.Split(paramString, "&") {
		key, val, _ := strings.Cut(param, "=")
		if strings.Contains(strings.ToLower(key), "pass") {
			newParams = append(newParams, key+"="+strings.Repeat("*", len(val)))
			continue
		}
		newParams = append(newParams, param)
	}
	return prefix + "?" + strings.Join(newParams, "&")
}

var supportedSubprotocols = map[string]func(string) (jdbc, error){
	"sqlite":     parseSqlite,
	"mysql":      parseMySQL,
	"postgresql": parsePostgres,
	"sqlserver":  parseSqlServer,
}

type jdbc interface {
	ping() bool
}

func newJDBC(conn string) (jdbc, error) {
	// expected format: "jdbc:{subprotocol}:{subname}"
	if !strings.HasPrefix(strings.ToLower(conn), "jdbc:") {
		return nil, errors.New("expected jdbc prefix")
	}
	conn = conn[len("jdbc:"):]
	subprotocol, subname, found := strings.Cut(conn, ":")
	if !found {
		return nil, errors.New("expected a colon separated subprotocol and subname")
	}
	// get the subprotocol parser
	parser, ok := supportedSubprotocols[strings.ToLower(subprotocol)]
	if !ok {
		return nil, errors.New("unsupported subprotocol")
	}
	return parser(subname)
}

func ping(driverName, conn string) bool {
	if err := pingErr(driverName, conn); err != nil {
		return false
	}
	return true
}

func pingErr(driverName, conn string) error {
	db, err := sql.Open(driverName, conn)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	return nil
}
