package mongodb

import (
	"context"
	"errors"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/mongo/driver/auth"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	timeout time.Duration // Zero value means "default timeout"
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultTimeout = 2 * time.Second
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	connStrPat = regexp.MustCompile(`\b(mongodb(?:\+srv)?://(?P<username>\S{3,50}):(?P<password>\S{3,88})@(?P<host>[-.%\w]+(?::\d{1,5})?(?:,[-.%\w]+(?::\d{1,5})?)*)(?:/(?P<authdb>[\w-]+)?(?P<options>\?\w+=[\w@/.$-]+(?:&(?:amp;)?\w+=[\w@/.$-]+)*)?)?)(?:\b|$)`)
	// TODO: Add support for sharded cluster, replica set and Atlas Deployment.
	placeholderPasswordPat = regexp.MustCompile(`^[xX]+|\*+$`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mongodb"}
}

// FromData will find and optionally verify MongoDB secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := connStrPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		// Filter out common placeholder passwords.
		password := match[3]
		if password == "" || placeholderPasswordPat.MatchString(password) {
			continue
		}

		// If the query string contains `&amp;` the options will not be parsed.
		resMatch := strings.Replace(strings.TrimSpace(match[1]), "&amp;", "&", -1)
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MongoDB,
			Raw:          []byte(resMatch),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/mongo/",
		}

		if verify {
			timeout := s.timeout
			if timeout == 0 {
				timeout = defaultTimeout
			}
			isVerified, verificationErr := verifyUri(resMatch, timeout)
			s1.Verified = isVerified
			if !isErrDeterminate(verificationErr) {
				s1.SetVerificationError(err, resMatch)
			}
		}
		results = append(results, s1)
	}

	return results, nil
}

func isErrDeterminate(err error) bool {
	var authErr *auth.Error
	return errors.As(err, &authErr)
}

func verifyUri(uri string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	clientOptions := options.Client().ApplyURI(uri)
	err := clientOptions.Validate()
	if err != nil {
		return false, err
	}

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = client.Disconnect(ctx)
	}()
	err = client.Ping(ctx, readpref.Primary())
	return err == nil, err
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MongoDB
}
