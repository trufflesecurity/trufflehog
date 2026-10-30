package boxoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

const tokenURL = "https://api.box.com/oauth2/token"

// maxSubjectIDCandidates bounds how many nearby subject IDs are tried per
// client ID and secret pair. Each candidate costs up to one token request per
// subject type, every request counts against the customer's Box API
// allocation, and a long run of failed subject attempts against one client
// looks like enumeration. Real configs usually carry one or two genuine IDs,
// and candidates are ranked so the most likely ones fall inside the cap.
const maxSubjectIDCandidates = 5

// subjectTypes are the box_subject_type values tried for each subject ID, in
// order. "enterprise" authenticates as the app's Service Account; "user"
// authenticates as an App User, Managed User or admin. User-subject tokens act
// as a real person, so dropping "user" here is the single switch for
// narrowing that footprint.
var subjectTypes = []string{"enterprise", "user"}

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	clientIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"id"}) + `\b([a-zA-Z0-9]{32})\b`)
	clientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret"}) + `\b([a-zA-Z0-9]{32})\b`)

	// Box enterprise and user IDs are numeric strings. The pattern mirrors
	// detectors.PrefixRegex(subjectKeywords) exactly, except that the keyword
	// group captures, so candidates can be ranked by which label they sit next
	// to without changing which numbers match.
	subjectKeywords = []string{"enterprise", "enterprise_id", "user", "user_id", "subject", "box_subject"}
	subjectIdPat    = regexp.MustCompile(`(?i:(` + strings.Join(subjectKeywords, "|") + `))(?:.|[\n\r]){0,40}?\b([0-9]{6,20})\b`)
)

// strongSubjectKeywords are labels that name a Box subject specifically.
// Numbers next to them are tried before numbers next to generic labels like
// "user", which also precede timestamps, phone numbers and unrelated IDs.
var strongSubjectKeywords = map[string]struct{}{
	"enterprise":    {},
	"enterprise_id": {},
	"box_subject":   {},
}

var (
	// errUnauthorizedClient is Box's unauthorized_client response to a request
	// carrying only the client ID and secret. Box defines it as "Client is not
	// authorized for requested grant type" and treats it as inconclusive: it
	// doesn't confirm the secret, so only a token issued for a subject can.
	errUnauthorizedClient = errors.New("unauthorized_client: Box only confirms these credentials by issuing a token for a nearby enterprise or user ID")

	// errInvalidClient is Box's invalid_client response, which Box defines as
	// an invalid client ID or secret. It's a definite rejection, so it never
	// surfaces as a verification error.
	errInvalidClient = errors.New("invalid_client")
)

// tokenErrorResponse is the OAuth 2.0 error body Box returns from the token endpoint.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"box"}
}

func (s Scanner) Description() string {
	return "Box is a service offering various service for secure collaboration, content management, and workflow. Box Oauth credentials can be used to access and interact with this data. " +
		"Box only confirms a client ID and secret by issuing a token for an enterprise or user ID, so these credentials verify only when such an ID appears nearby."
}

// FromData will find and optionally verify Box secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueIdMatches := make(map[string]struct{})
	for _, match := range clientIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIdMatches[match[1]] = struct{}{}
	}

	uniqueSecretMatches := make(map[string]struct{})
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	subjectIds := rankSubjectIDs(dataStr)

	for resIdMatch := range uniqueIdMatches {
		for resSecretMatch := range uniqueSecretMatches {
			if resIdMatch == resSecretMatch {
				continue
			}

			s1 := detectors.Result{
				DetectorType: s.Type(),
				Raw:          []byte(resIdMatch),
				RawV2:        []byte(resIdMatch + resSecretMatch),
				SecretParts: map[string]string{
					"client_id":     resIdMatch,
					"client_secret": resSecretMatch,
				},
			}

			if verify {
				isVerified, subjectId, verificationErr := verifyMatch(ctx, s.getClient(), resIdMatch, resSecretMatch, subjectIds)
				s1.Verified = isVerified
				// subject_id feeds the Box analyzer, which needs the same
				// subject to authenticate, so it's only recorded once Box has
				// accepted it.
				if subjectId != "" {
					s1.SecretParts["subject_id"] = subjectId
				}
				s1.SetVerificationError(verificationErr, resIdMatch, resSecretMatch)
			}

			results = append(results, s1)

			// box client supports only one client id and secret pair
			if s1.Verified {
				break
			}
		}
	}

	return
}

// verifyMatch applies Box's verification rules to one client ID and secret
// pair, as Box defines them:
//
//   - invalid_client on the subject-less request: unverified (dead).
//   - unauthorized_client: inconclusive on its own. The pair is Verified only
//     when a request naming a nearby subject ID returns HTTP 200. If there's no
//     subject ID, or every subject attempt fails, the result stays unknown,
//     because Box won't say whether the secret or the subject caused a failure.
//   - Any other response: unknown, with no subject requests.
//
// It returns the accepted subject ID alongside a Verified result.
func verifyMatch(ctx context.Context, client *http.Client, id, secret string, subjectIds []string) (bool, string, error) {
	err := probeClientCredentials(ctx, client, id, secret)
	switch {
	case errors.Is(err, errInvalidClient):
		return false, "", nil
	case !errors.Is(err, errUnauthorizedClient):
		return false, "", err
	}

	if len(subjectIds) == 0 {
		return false, "", err
	}

	candidates := subjectIds
	if len(candidates) > maxSubjectIDCandidates {
		candidates = candidates[:maxSubjectIDCandidates]
	}

	for _, subjectId := range candidates {
		if verifySubjectID(ctx, client, id, secret, subjectId) {
			return true, subjectId, nil
		}
	}

	// These messages use %v, not %w: Result.SetVerificationError keeps only the
	// innermost wrapped error, which would drop the context added here.
	msg := fmt.Sprintf("%v; no nearby subject ID was accepted", err)
	// When the cap skipped candidates, say so, so an unknown result on a noisy
	// chunk is explainable. Counts only: the IDs themselves stay out of the
	// stored error.
	if len(subjectIds) > len(candidates) {
		msg = fmt.Sprintf("%s (tried %d of %d subject ID candidates)", msg, len(candidates), len(subjectIds))
	}
	return false, "", errors.New(msg)
}

// probeClientCredentials sends the client ID and secret to Box's token
// endpoint without a subject. Box requires a subject for client-credentials
// tokens, so this request never issues one; its only purpose is to sort the
// pair into Box's rule buckets. It returns errInvalidClient,
// errUnauthorizedClient, or an error describing an unexpected response.
func probeClientCredentials(ctx context.Context, client *http.Client, id string, secret string) error {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {id},
		"client_secret": {secret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	var tokenErr tokenErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&tokenErr); err != nil {
		return fmt.Errorf("failed to decode token error response: %v", err)
	}

	switch tokenErr.Error {
	case "invalid_client":
		return errInvalidClient
	case "unauthorized_client":
		return errUnauthorizedClient
	default:
		return fmt.Errorf("unexpected token error %q", tokenErr.Error)
	}
}

// verifySubjectID checks whether a subject ID is valid for the given client
// credentials by attempting the Box CCG (Client Credentials Grant) auth flow.
// It mirrors the analyzer's Authenticate logic: try each of subjectTypes in
// order, and return true on the first successful authentication (HTTP 200).
//
// A 200 means Box issued a real access token, valid for 60 minutes with no
// refresh token. That's unavoidable: Box confirmed that a token issued for a
// subject is the only valid verification signal. The body is drained without
// being parsed, so the token never reaches results, logs or errors. It is
// deliberately not revoked. Revoking would add another request against the
// customer's API allocation and another audit event, and the token never
// leaves this process, so it is left to expire on its own.
func verifySubjectID(ctx context.Context, client *http.Client, clientID, clientSecret, subjectID string) bool {
	for _, subjectType := range subjectTypes {
		form := url.Values{
			"grant_type":       {"client_credentials"},
			"client_id":        {clientID},
			"client_secret":    {clientSecret},
			"box_subject_type": {subjectType},
			"box_subject_id":   {subjectID},
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		res, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()

		if res.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}

// rankSubjectIDs returns the unique subject ID candidates in data, ordered so
// the ones most likely to be a real Box subject come first. Numbers labeled
// with a strong keyword (see strongSubjectKeywords) go ahead of numbers next to
// generic labels. Within each group, numbers keep the order they appear in the
// text, which keeps the result deterministic and keeps a config's own ID near
// the front. A number seen under both kinds of label counts as strong.
func rankSubjectIDs(data string) []string {
	var order []string
	strong := make(map[string]bool)
	for _, match := range subjectIdPat.FindAllStringSubmatch(data, -1) {
		keyword, subjectId := strings.ToLower(match[1]), match[2]
		_, isStrong := strongSubjectKeywords[keyword]
		if seenStrong, seen := strong[subjectId]; seen {
			strong[subjectId] = seenStrong || isStrong
			continue
		}
		strong[subjectId] = isStrong
		order = append(order, subjectId)
	}

	ranked := make([]string, 0, len(order))
	for _, subjectId := range order {
		if strong[subjectId] {
			ranked = append(ranked, subjectId)
		}
	}
	for _, subjectId := range order {
		if !strong[subjectId] {
			ranked = append(ranked, subjectId)
		}
	}
	return ranked
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_BoxOauth
}
