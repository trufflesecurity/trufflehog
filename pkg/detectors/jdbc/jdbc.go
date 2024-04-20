package jdbc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	ignorePatterns []regexp.Regexp
}

func New(opts ...func(*Scanner)) *Scanner {
	scanner := &Scanner{
		ignorePatterns: []regexp.Regexp{},
	}
	for _, opt := range opts {
		opt(scanner)
	}

	return scanner
}

func WithIgnorePattern(ignoreStrings []string) func(*Scanner) {
	return func(s *Scanner) {
		var ignorePatterns []regexp.Regexp
		for _, ignoreString := range ignoreStrings {
			ignorePattern, err := regexp.Compile(ignoreString)
			if err != nil {
				panic(fmt.Sprintf("%s is not a valid regex, error received: %v", ignoreString, err))
			}
			ignorePatterns = append(ignorePatterns, *ignorePattern)
		}

		s.ignorePatterns = ignorePatterns
	}
}

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
matchLoop:
	for _, match := range matches {
		if len(s.ignorePatterns) != 0 {
			for _, ignore := range s.ignorePatterns {
				if ignore.MatchString(match[0]) {
					continue matchLoop
				}
			}
		}
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
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			pingRes := j.ping(ctx)
			s.Verified = pingRes.err == nil
			// If there's a ping error that is marked as "determinate" we throw it away. We do this because this was the
			// behavior before tri-state verification was introduced and preserving it allows us to gradually migrate
			// detectors to use tri-state verification.
			if pingRes.err != nil && !pingRes.determinate {
				err = pingRes.err
				s.SetVerificationError(err, jdbcConn)
			}
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
	if s, ok := tryRedactURLParams(conn); ok {
		return s
	}
	if s, ok := tryRedactODBC(conn); ok {
		return s
	}
	if s, ok := tryRedactBasicAuth(conn); ok {
		return s
	}
	if s, ok := tryRedactRegex(conn); ok {
		return s
	}
	return conn
}

// Basic authentication "username:password@host" style
func tryRedactBasicAuth(conn string) (string, bool) {
	userPass, postfix, found := strings.Cut(conn, "@")
	if !found {
		return "", false
	}
	index := strings.LastIndex(userPass, ":")
	if index == -1 {
		return "", false
	}
	prefix, pass := userPass[:index], userPass[index+1:]
	return prefix + ":" + strings.Repeat("*", len(pass)) + "@" + postfix, true
}

// URL param "?password=password" style
func tryRedactURLParams(conn string) (string, bool) {
	prefix, paramString, found := strings.Cut(conn, "?")
	if !found {
		return "", false
	}
	var newParams []string
	found = false
	for _, param := range strings.Split(paramString, "&") {
		key, val, _ := strings.Cut(param, "=")
		if strings.Contains(strings.ToLower(key), "pass") {
			newParams = append(newParams, key+"="+strings.Repeat("*", len(val)))
			found = true
			continue
		}
		newParams = append(newParams, param)
	}
	if !found {
		return "", false
	}
	return prefix + "?" + strings.Join(newParams, "&"), true
}

// ODBC params ";password=password" style
func tryRedactODBC(conn string) (string, bool) {
	var found bool
	var newParams []string
	for _, param := range strings.Split(conn, ";") {
		key, val, isKvp := strings.Cut(param, "=")
		if isKvp && strings.Contains(strings.ToLower(key), "pass") {
			newParams = append(newParams, key+"="+strings.Repeat("*", len(val)))
			found = true
			continue
		}
		newParams = append(newParams, param)
	}
	if !found {
		return "", false
	}
	return strings.Join(newParams, ";"), true
}

// Naively search the string for "pass="
func tryRedactRegex(conn string) (string, bool) {
	pattern := regexp.MustCompile(`(?i)pass.*?=(.+?)\b`)
	var found bool
	newConn := pattern.ReplaceAllStringFunc(conn, func(s string) string {
		index := strings.Index(s, "=")
		if index == -1 {
			// unreachable due to regex containing '='
			return s
		}
		found = true
		return s[:index+1] + strings.Repeat("*", len(s[index+1:]))
	})
	if !found {
		return "", false
	}
	return newConn, true
}

var supportedSubprotocols = map[string]func(string) (jdbc, error){
	"mysql":      parseMySQL,
	"postgresql": parsePostgres,
	"sqlserver":  parseSqlServer,
}

type pingResult struct {
	err         error
	determinate bool
}

type jdbc interface {
	ping(context.Context) pingResult
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

func ping(ctx context.Context, driverName string, isDeterminate func(error) bool, candidateConns ...string) pingResult {
	var indeterminateErrors []error
	for _, c := range candidateConns {
		err := pingErr(ctx, driverName, c)
		if err == nil || isDeterminate(err) {
			return pingResult{err, true}
		}
		indeterminateErrors = append(indeterminateErrors, err)
	}
	return pingResult{errors.Join(indeterminateErrors...), false}
}

func pingErr(ctx context.Context, driverName, conn string) error {
	db, err := sql.Open(driverName, conn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return err
	}
	return nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JDBC
}
