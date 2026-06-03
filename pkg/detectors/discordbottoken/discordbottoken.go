package discordbottoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// A Discord bot token is three base64url segments: the bot's user ID, a
	// timestamp, and an HMAC. Segment lengths vary across token generations (the
	// ID segment tracks the snowflake size and the HMAC segment was lengthened in
	// 2022), so the ranges below stay deliberately loose. The bot ID is embedded
	// in the first segment, so no separate ID needs to be matched.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"discord"}) + `\b([A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"discord"}
}

// FromData will find and optionally verify DiscordBotToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DiscordBotToken,
			Raw:          []byte(token),
			Redacted:     decodeBotID(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			verified, extraData, vErr := verifyDiscordToken(ctx, client, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			if vErr != nil {
				s1.SetVerificationError(vErr, token)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

// decodeBotID extracts the bot's user ID, which Discord encodes as the first
// segment of the token (base64url of the snowflake ID). Returns "" if the segment
// can't be decoded into a numeric ID.
func decodeBotID(token string) string {
	first, _, found := strings.Cut(token, ".")
	if !found {
		return ""
	}

	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		return ""
	}

	id := string(decoded)
	for _, r := range id {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return id
}

type botUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// verifyDiscordToken validates a bot token against the current /users/@me endpoint.
// Using @me avoids needing a separately-parsed bot ID: the token authenticates as
// the bot, and Discord returns the bot's own user object.
func verifyDiscordToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bot %s", token))

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var u botUser
		if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
			// Credentials are valid (200); report verified even without the optional context.
			return true, nil, nil
		}
		if u.ID == "" && u.Username == "" {
			return true, nil, nil
		}
		return true, map[string]string{"bot_id": u.ID, "username": u.Username}, nil
	case http.StatusUnauthorized:
		// Invalid or revoked token.
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DiscordBotToken
}

func (s Scanner) Description() string {
	return "Discord bot tokens are used to authenticate and control Discord bots. These tokens can be used to interact with the Discord API to perform various bot-related operations."
}
