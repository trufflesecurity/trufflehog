package custom_detectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp" //nolint:depguard // used instead of github.com/wasilibs/go-re2 due to differences in utf-8 handling
	"slices"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// The maximum number of matches from one chunk. This const is used when
// permutating each regex match to protect the scanner from doing too much work
// for poorly defined regexps.
const maxTotalMatches = 100

// ─── OAuth2 token acquisition ────────────────────────────────────────

// ropcTokenSource implements oauth2.TokenSource for the Resource Owner
// Password Credentials grant (RFC 6749 Section 4.3). Caching and
// expiry are handled by oauth2.ReuseTokenSource; this type only
// performs the token exchange.
type ropcTokenSource struct {
	conf     *oauth2.Config
	username string
	password string
	// httpCtx carries both the HTTP client (via the oauth2.HTTPClient
	// context key) and the structured logger with oauth2_trace set.
	// Token acquisition logs inherit the trace automatically.
	//
	// This context is rooted in Background rather than the per-scan
	// detection context because oauth2.TokenSource.Token() accepts no
	// context parameter — there is no way to thread a caller-provided
	// context through the interface. The SaneHttpClient timeout bounds
	// the worst case for a stuck token endpoint.
	httpCtx context.Context
}

func (s *ropcTokenSource) Token() (*oauth2.Token, error) {
	logger := logContext.AddLogger(s.httpCtx).Logger()
	logger.Info("requesting ROPC token from endpoint",
		"token_endpoint", s.conf.Endpoint.TokenURL,
		"client_id", s.conf.ClientID,
	)
	tok, err := s.conf.PasswordCredentialsToken(s.httpCtx, s.username, s.password)
	if err != nil {
		logger.Error(err, "ROPC token acquisition failed",
			"token_endpoint", s.conf.Endpoint.TokenURL,
			"client_id", s.conf.ClientID,
		)
		return nil, err
	}
	logger.Info("ROPC token acquired successfully",
		"token_endpoint", s.conf.Endpoint.TokenURL,
		"token_type", tok.TokenType,
		"expires_in", tok.Expiry,
	)
	return tok, nil
}

// newROPCTokenSource builds an oauth2.TokenSource for the ROPC grant,
// wrapped in ReuseTokenSource for automatic caching with a 10-second
// expiry buffer. The provided ctx already carries oauth2_trace on its
// logger; the HTTP client is added here for token endpoint requests.
func newROPCTokenSource(ctx logContext.Context, oc *custom_detectorspb.OAuth2Config, ropc *custom_detectorspb.ROPCConfig) oauth2.TokenSource {
	conf := &oauth2.Config{
		ClientID:     ropc.GetClientId(),
		ClientSecret: ropc.GetClientSecret(),
		Endpoint: oauth2.Endpoint{
			TokenURL:  oc.GetTokenEndpoint(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	if scope := ropc.GetScope(); scope != "" {
		conf.Scopes = strings.Split(scope, " ")
	}
	// Add the SaneHttpClient for TLS/timeout settings. The HTTPClient
	// key is non-string, so it passes through WithValue without
	// polluting the structured logger.
	httpCtx := logContext.WithValue(ctx, oauth2.HTTPClient, httpClient)
	base := &ropcTokenSource{
		conf:     conf,
		username: ropc.GetUsername(),
		password: ropc.GetPassword(),
		httpCtx:  httpCtx,
	}
	return oauth2.ReuseTokenSource(nil, base)
}

// customDetectorVerifier binds a VerifierConfig to an optional
// OAuth2TokenSource. This avoids parallel slices and ensures the auth
// config can never get out of sync with its verifier.
type customDetectorVerifier struct {
	config      *custom_detectorspb.VerifierConfig
	tokenSource detectors.OAuth2TokenSource // nil when no auth is configured
}

// BuildTokenSource creates the appropriate OAuth2TokenSource for a
// VerifierConfig's auth block. Returns (nil, nil) when no auth is
// configured. Returns a non-nil error when auth is configured but
// the grant type is unrecognized or unusable. Exported so the
// external callers can build token sources from proto config
// without duplicating grant-type logic.
func BuildTokenSource(auth *custom_detectorspb.VerifierAuth) (detectors.OAuth2TokenSource, error) {
	if auth == nil {
		return nil, nil
	}
	switch ac := auth.GetAuthConfig().(type) {
	case *custom_detectorspb.VerifierAuth_Oauth2:
		return buildOAuth2TokenSource(ac.Oauth2)
	default:
		return nil, fmt.Errorf("unrecognized auth config type: %T", auth.GetAuthConfig())
	}
}

// buildOAuth2TokenSource dispatches to the correct grant-type builder
// based on which oneof field is set on the OAuth2Config.
func buildOAuth2TokenSource(oc *custom_detectorspb.OAuth2Config) (detectors.OAuth2TokenSource, error) {
	if oc == nil {
		return nil, fmt.Errorf("oauth2 config is nil")
	}
	// Generate the trace ID once. It rides on the TracedTokenSource
	// wrapper so verification sites can extract it, and on the token
	// source's internal httpCtx so token acquisition logs inherit it.
	ts := &detectors.TracedTokenSource{Trace: common.RandomID(8)}
	ctx := ts.EnrichContext(logContext.Background())
	logger := ctx.Logger()
	switch cfg := oc.GetGrantConfig().(type) {
	case *custom_detectorspb.OAuth2Config_Ropc:
		logger.Info("building ROPC token source",
			"token_endpoint", oc.GetTokenEndpoint(),
			"client_id", cfg.Ropc.GetClientId(),
			"has_scope", cfg.Ropc.GetScope() != "",
		)
		ts.TokenSource = newROPCTokenSource(ctx, oc, cfg.Ropc)
		return ts, nil
	default:
		return nil, fmt.Errorf("unrecognized OAuth2 grant type: %T", oc.GetGrantConfig())
	}
}

// ─── Request body template ──────────────────────────────────────────

// knownTokens lists the $token references supported in a
// VerifyRequestBody template. Values are substituted at verification
// time from the detected result and (optionally) the OAuth2 token.
var knownTokens = map[string]bool{
	"$secret":        true,
	"$detector_type": true,
	"$detector_name": true,
	"$token":         true,
}

// validateRequestBody checks that every $-prefixed value in the body
// template references a known token. Called at init time so typos
// surface as startup errors rather than silent verification failures.
func validateRequestBody(body map[string]string) error {
	for key, val := range body {
		if strings.HasPrefix(val, "$") && !knownTokens[val] {
			return fmt.Errorf("unknown token %q in request body field %q; supported tokens: $secret, $detector_type, $detector_name, $token", val, key)
		}
	}
	return nil
}

// ResolveRequestBody substitutes $token references in the body
// template with their runtime values and returns the JSON-encoded
// result. Non-token values pass through as-is. Exported so the
// engine OAuth verification path can use the same logic.
func ResolveRequestBody(template map[string]string, vars map[string]string) ([]byte, error) {
	resolved := make(map[string]string, len(template))
	for key, val := range template {
		if strings.HasPrefix(val, "$") {
			if replacement, ok := vars[val]; ok {
				resolved[key] = replacement
			} else {
				// Validated at init, so this should not happen.
				resolved[key] = ""
			}
		} else {
			resolved[key] = val
		}
	}
	return json.Marshal(resolved)
}

// ─── Custom detector ─────────────────────────────────────────────────

// CustomRegexWebhook is a CustomRegex with webhook validation that is
// guaranteed to be valid (assuming the data is not changed after
// initialization).
type CustomRegexWebhook struct {
	*custom_detectorspb.CustomRegex
	// verifiers pairs each VerifierConfig with its optional token source.
	// Built once in NewWebhookCustomRegex; used in createResults.
	verifiers []customDetectorVerifier
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*CustomRegexWebhook)(nil)
var _ detectors.CustomFalsePositiveChecker = (*CustomRegexWebhook)(nil)
var _ detectors.MaxSecretSizeProvider = (*CustomRegexWebhook)(nil)

// NewWebhookCustomRegex initializes and validates a CustomRegexWebhook. An
// unexported type is intentionally returned here to ensure the values have
// been validated.
func NewWebhookCustomRegex(pb *custom_detectorspb.CustomRegex) (*CustomRegexWebhook, error) {
	// TODO: Return all validation errors.
	if err := ValidateKeywords(pb.Keywords); err != nil {
		return nil, err
	}
	if err := ValidateRegex(pb.Regex); err != nil {
		return nil, err
	}
	if err := ValidateRegexSlice(pb.ExcludeRegexesCapture); err != nil {
		return nil, err
	}
	if err := ValidateRegexSlice(pb.ExcludeRegexesMatch); err != nil {
		return nil, err
	}
	if err := ValidatePrimaryRegexName(pb.PrimaryRegexName, pb.Regex); err != nil {
		return nil, err
	}

	for _, verify := range pb.Verify {
		if err := ValidateVerifyEndpoint(verify.Endpoint, verify.Unsafe); err != nil {
			return nil, err
		}
		// The verifier's unsafe flag covers the entire communication
		// chain, including the auth token endpoint. Sending credentials
		// over plaintext is at least as dangerous as verification over
		// plaintext, so both are gated by the same flag.
		if oc := verify.GetAuth().GetOauth2(); oc != nil {
			if err := ValidateVerifyEndpoint(oc.GetTokenEndpoint(), verify.Unsafe); err != nil {
				return nil, fmt.Errorf("auth token endpoint: %w", err)
			}
		}
		if err := ValidateVerifyHeaders(verify.Headers); err != nil {
			return nil, err
		}
		if err := ValidateVerifyRanges(verify.SuccessRanges); err != nil {
			return nil, err
		}
		if err := ValidateVerifyRanges(verify.RotatedRanges); err != nil {
			return nil, err
		}
	}

	// Ensure primary regex name is set.
	ensurePrimaryRegexNameSet(pb)

	// Build the verifier slice, pairing each VerifierConfig with its
	// token source (nil when auth isn't configured).
	verifiers := make([]customDetectorVerifier, 0, len(pb.GetVerify()))
	for _, vc := range pb.GetVerify() {
		ts, err := BuildTokenSource(vc.GetAuth())
		if err != nil {
			return nil, fmt.Errorf("verifier %q: %w", vc.GetEndpoint(), err)
		}
		// Validate request body template tokens at init time so
		// typos are caught at startup rather than at verification.
		if req := vc.GetRequest(); req != nil && len(req.GetBody()) > 0 {
			if err := validateRequestBody(req.GetBody()); err != nil {
				return nil, fmt.Errorf("verifier %q: %w", vc.GetEndpoint(), err)
			}
		}
		verifiers = append(verifiers, customDetectorVerifier{
			config:      vc,
			tokenSource: ts,
		})
	}

	// TODO: Copy only necessary data out of pb.
	return &CustomRegexWebhook{
		CustomRegex: pb,
		verifiers:   verifiers,
	}, nil
}

var httpClient = common.SaneHttpClient()

func (c *CustomRegexWebhook) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	regexMatches := make(map[string][][]string, len(c.GetRegex()))

	// Compile exclude regexes targeting the capture group
	excludeRegexesCapture := make([]*regexp.Regexp, 0, len(c.GetExcludeRegexesCapture()))
	for _, exclude := range c.GetExcludeRegexesCapture() {
		regex, err := regexp.Compile(exclude)
		if err != nil {
			// This will only happen if the regex is invalid.
			return nil, err
		}
		excludeRegexesCapture = append(excludeRegexesCapture, regex)
	}

	// Compile exclude regexes targeting the entire match
	excludeRegexes := make([]*regexp.Regexp, 0, len(c.GetExcludeRegexesMatch()))
	for _, exclude := range c.GetExcludeRegexesMatch() {
		regex, err := regexp.Compile(exclude)
		if err != nil {
			// This will only happen if the regex is invalid.
			return nil, err
		}
		excludeRegexes = append(excludeRegexes, regex)
	}

	// Find all submatches for each regex.
	for name, regex := range c.GetRegex() {
		regex, err := regexp.Compile(regex)
		if err != nil {
			// This will only happen if the regex is invalid.
			return nil, err
		}
		regexMatches[name] = regex.FindAllStringSubmatch(dataStr, -1)
	}

	// Permutate each individual match.
	// {
	//    "foo": [["match1"]]
	//    "bar": [["match2"], ["match3"]]
	// }
	// becomes
	// [
	//    {"foo": ["match1"], "bar": ["match2"]},
	//    {"foo": ["match1"], "bar": ["match3"]},
	// ]
	matches := permutateMatches(regexMatches)

	g := new(errgroup.Group)

	// Create result object and test for verification.
	resultsCh := make(chan detectors.Result, maxTotalMatches)

MatchLoop:
	for _, match := range matches {
		for key, values := range match {
			// attempt to use capture group
			secret := values[0]
			if len(values) > 1 {
				secret = values[1]
			}

			// check entropy
			entropy := c.GetEntropy()
			if entropy > 0.0 && detectors.StringShannonEntropy(secret) < float64(entropy) {
				continue MatchLoop
			}

			// check for exclude words
			for _, excludeWord := range c.GetExcludeWords() {
				if strings.Contains(strings.ToLower(secret), excludeWord) {
					continue MatchLoop
				}
			}

			// exclude checks
			for _, excludeMatch := range excludeRegexes {
				if excludeMatch.MatchString(values[0]) {
					continue MatchLoop
				}
			}

			// exclude secret (capture group), or if no capture group is set,
			// check against entire match.
			for _, excludeSecret := range excludeRegexesCapture {
				if excludeSecret.MatchString(secret) {
					continue MatchLoop
				}
			}

			if validations := c.GetValidations(); validations != nil {
				validationRules := []struct {
					enabled   bool
					validator func(string) bool
				}{
					{validations[key].GetContainsDigit(), ContainsDigit},
					{validations[key].GetContainsLowercase(), ContainsLowercase},
					{validations[key].GetContainsUppercase(), ContainsUppercase},
					{validations[key].GetContainsSpecialChar(), ContainsSpecialChar},
				}

				for _, rule := range validationRules {
					if rule.enabled && !rule.validator(secret) {
						// skip this match if a validation rule is enabled but missing from the secret
						continue MatchLoop
					}
				}
			}

		}

		g.Go(func() error {
			return c.createResults(ctx, match, verify, resultsCh)
		})
	}

	// Ignore any errors and collect as many of the results as we can.
	_ = g.Wait()
	close(resultsCh)

	for result := range resultsCh {
		if result.ExtraData != nil {
			result.ExtraData["name"] = c.GetName()
		}

		results = append(results, result)
	}

	return results, nil
}

func (c *CustomRegexWebhook) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

// custom max size for custom detector
func (c *CustomRegexWebhook) MaxSecretSize() int64 {
	return 1000
}

func (c *CustomRegexWebhook) createResults(ctx context.Context, match map[string][]string, verify bool, results chan<- detectors.Result) error {
	if common.IsDone(ctx) {
		// TODO: Log we're possibly leaving out results.
		return ctx.Err()
	}

	result := detectors.Result{
		DetectorType: detector_typepb.DetectorType_CustomRegex,
		DetectorName: c.GetName(),
		ExtraData:    map[string]string{},
	}

	var raw string
	for _, key := range slices.Sorted(maps.Keys(match)) {
		values := match[key]
		// values[0] contains the entire regex match.
		secret := values[0]
		fullMatch := values[0]
		if len(values) > 1 {
			secret = values[1]
		}
		raw += secret

		// We set the full regex match as the primary secret value.
		// Reasoning:
		// The engine calculates the line number using the match. When a primary secret is set, it uses that value instead of the raw secret.
		// While the secret match itself is sufficient to calculate the line number, the same group match could appear elsewhere in the data.
		// To avoid ambiguity, we store the full regex match as the primary secret value.
		// This primary secret value is used only for identifying the exact line number and is not used anywhere else.

		// Example:
		// Full regex match: secret = ABC123
		// Secret (raw): ABC123

		// In this case, the primary secret value stores the full string `secret = ABC123`,
		// allowing the engine to pinpoint the exact location and avoid matching redundant occurrences of `ABC123` in the data.
		if c.PrimaryRegexName == key {
			result.SetPrimarySecretValue(fullMatch)
		}
	}

	result.Raw = []byte(raw)

	if !verify {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case results <- result:
			return nil
		}
	}
	// Verify via webhook.
	// Default body uses the existing format: detector name → regex match
	// groups. Verifiers with a custom request.body template override this
	// per-verifier inside the shared verification loop.
	defaultBody, err := json.Marshal(map[string]map[string][]string{
		c.GetName(): match,
	})
	if err != nil {
		// This should never happen, but if it does, return nil to not
		// disrupt other verification.
		return nil
	}

	// Build the shared VerifyEndpoint slice from the detector's
	// proto verifier configs. Each verifier can have its own endpoint,
	// headers, status code ranges, body template, and token source.
	endpoints := make([]VerifyEndpoint, len(c.verifiers))
	for i, v := range c.verifiers {
		ep := VerifyEndpoint{
			URL:           v.config.GetEndpoint(),
			Headers:       v.config.GetHeaders(),
			SuccessRanges: v.config.GetSuccessRanges(),
			RotatedRanges: v.config.GetRotatedRanges(),
			TokenSource:   v.tokenSource,
		}
		if req := v.config.GetRequest(); req != nil {
			ep.Body = req.GetBody()
		}
		endpoints[i] = ep
	}

	vars := map[string]string{
		"$secret":        string(result.Raw),
		"$detector_type": result.DetectorType.String(),
		"$detector_name": result.DetectorName,
	}

	outcome := VerifyCredential(ctx, httpClient, endpoints, defaultBody, vars)
	result.Verified = outcome.Verified
	if outcome.RespBody != "" {
		result.ExtraData["response"] = outcome.RespBody
	}
	if !outcome.Definitive && outcome.RangesInEffect {
		// At least one endpoint used ranges but none matched.
		result.SetVerificationError(errors.New("verification response status code did not match any configured successRanges or rotatedRanges"))
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case results <- result:
		return nil
	}
}

func (c *CustomRegexWebhook) Keywords() []string {
	return c.GetKeywords()
}

// productIndices produces a permutation of indices for each length. Example:
// productIndices(3, 2) -> [[0 0] [1 0] [2 0] [0 1] [1 1] [2 1]]. It returns
// a slice of length no larger than maxTotalMatches.
func productIndices(lengths ...int) [][]int {
	count := 1
	for _, l := range lengths {
		count *= l
	}
	if count == 0 {
		return nil
	}
	if count > maxTotalMatches {
		count = maxTotalMatches
	}

	results := make([][]int, count)
	for i := 0; i < count; i++ {
		j := 1
		result := make([]int, 0, len(lengths))
		for _, l := range lengths {
			result = append(result, (i/j)%l)
			j *= l
		}
		results[i] = result
	}
	return results
}

// permutateMatches converts the list of all regex matches into all possible
// permutations selecting one from each named entry in the map. For example:
// {"foo": [matchA, matchB], "bar": [matchC]} becomes
//
// [{"foo": matchA, "bar": matchC}, {"foo": matchB, "bar": matchC}]
func permutateMatches(regexMatches map[string][][]string) []map[string][]string {
	// Get a consistent order for names and their matching lengths.
	// The lengths are used in calculating the permutation so order matters.
	names := make([]string, 0, len(regexMatches))
	lengths := make([]int, 0, len(regexMatches))
	for key, value := range regexMatches {
		names = append(names, key)
		lengths = append(lengths, len(value))
	}

	// Permutate all the indices for each match. For example, if "foo" has
	// [matchA, matchB] and "bar" has [matchC], we will get indices [0 0] [1 0].
	permutationIndices := productIndices(lengths...)

	// Build {"foo": matchA, "bar": matchC} and {"foo": matchB, "bar": matchC}
	// from the indices.
	var matches []map[string][]string
	for _, permutation := range permutationIndices {
		candidate := make(map[string][]string, len(permutationIndices))
		for i, name := range names {
			candidate[name] = regexMatches[name][permutation[i]]
		}
		matches = append(matches, candidate)
	}

	return matches
}

func (c *CustomRegexWebhook) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CustomRegex
}

const defaultDescription = "This is a user-defined detector with no description provided."

func (c *CustomRegexWebhook) Description() string {
	if c.GetDescription() == "" {
		return defaultDescription
	}
	return c.GetDescription()
}

// ensurePrimaryRegexNameSet sets the PrimaryRegexName field to the
// first regex name in sorted order if it is not already set.
// We're sorting to ensure deterministic behavior.
func ensurePrimaryRegexNameSet(pb *custom_detectorspb.CustomRegex) {
	if pb.PrimaryRegexName == "" {
		for _, name := range slices.Sorted(maps.Keys(pb.Regex)) {
			pb.PrimaryRegexName = name
			return
		}
	}
}
