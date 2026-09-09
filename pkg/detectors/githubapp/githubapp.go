package githubapp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	lru "github.com/hashicorp/golang-lru/v2"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Scanner struct {
	perSource sync.Map
	lastReap  atomic.Int64
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.MaxSecretSizeProvider = (*Scanner)(nil)
var _ detectors.MultiPartCredentialProvider = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

const (
	maxSecretSize     = 4096
	maxCredentialSpan = 4096

	perSourceHalfCap = 256
	sourceTTL        = 30 * time.Minute
	reapInterval     = 5 * time.Minute
)

type halfInfo struct {
	value    string
	location string
}

type sourceState struct {
	mu        sync.Mutex
	pems      *lru.Cache[string, halfInfo]
	appIDs    *lru.Cache[string, halfInfo]
	lastTouch atomic.Int64
}

func newSourceState() *sourceState {
	p, err := lru.New[string, halfInfo](perSourceHalfCap)
	if err != nil {
		panic(fmt.Errorf("githubapp: lru.New pems: %w", err))
	}
	a, err := lru.New[string, halfInfo](perSourceHalfCap)
	if err != nil {
		panic(fmt.Errorf("githubapp: lru.New appIDs: %w", err))
	}
	return &sourceState{pems: p, appIDs: a}
}

func (s *Scanner) stateFor(sid sources.SourceID) *sourceState {
	if v, ok := s.perSource.Load(sid); ok {
		return v.(*sourceState)
	}
	fresh := newSourceState()
	actual, _ := s.perSource.LoadOrStore(sid, fresh)
	return actual.(*sourceState)
}

func (s *Scanner) maybeReap(now time.Time) {
	last := s.lastReap.Load()
	nowNS := now.UnixNano()
	if nowNS-last < int64(reapInterval) {
		return
	}
	if !s.lastReap.CompareAndSwap(last, nowNS) {
		return
	}
	cutoff := nowNS - int64(sourceTTL)
	s.perSource.Range(func(k, v any) bool {
		state := v.(*sourceState)
		if state.lastTouch.Load() < cutoff {
			s.perSource.Delete(k)
		}
		return true
	})
}

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?-----\s*?END[ A-Z0-9_-]*?PRIVATE KEY\s*?-----`)
	appPat = regexp.MustCompile(`(?i)(?:github[-_ ]?app[-_ ]?id|gh[-_ ]?app[-_ ]?id|app[-_ ]?id)\W{1,5}([0-9]{4,9})\b`)
)

func (s *Scanner) Keywords() []string {
	return []string{"github", "private key"}
}

func (s *Scanner) MaxSecretSize() int64     { return maxSecretSize }
func (s *Scanner) MaxCredentialSpan() int64 { return maxCredentialSpan }

func (s *Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllString(dataStr, -1)
	appMatches := appPat.FindAllStringSubmatch(dataStr, -1)
	if len(keyMatches) == 0 && len(appMatches) == 0 {
		return nil, nil
	}

	chunkPEMs := make(map[string]string)
	for _, k := range keyMatches {
		trimmed := strings.TrimSpace(k)
		if !isGitHubAppKeyShape(trimmed) {
			continue
		}
		chunkPEMs[pemFingerprint(trimmed)] = trimmed
	}
	chunkAppIDs := make(map[string]struct{})
	for _, a := range appMatches {
		chunkAppIDs[strings.TrimSpace(a[1])] = struct{}{}
	}
	if len(chunkPEMs) == 0 && len(chunkAppIDs) == 0 {
		return nil, nil
	}

	var results []detectors.Result

	for _, pemStr := range chunkPEMs {
		for appID := range chunkAppIDs {
			results = append(results, makeResult(ctx, pemStr, appID, "", "in-chunk", verify))
		}
	}

	sid, hasSource := sourceIDFromCtx(ctx)
	if !hasSource {
		return results, nil
	}

	now := time.Now()
	s.maybeReap(now)
	state := s.stateFor(sid)
	state.lastTouch.Store(now.UnixNano())
	companionLoc := sourceMetadataFromCtx(ctx)

	type pairCandidate struct {
		pem, appID, companionLoc string
	}
	var pairs []pairCandidate

	state.mu.Lock()
	for _, pemStr := range chunkPEMs {
		for _, appKey := range state.appIDs.Keys() {
			if _, inChunk := chunkAppIDs[appKey]; inChunk {
				continue
			}
			cached, ok := state.appIDs.Get(appKey)
			if !ok {
				continue
			}
			pairs = append(pairs, pairCandidate{
				pem: pemStr, appID: appKey, companionLoc: cached.location,
			})
		}
	}
	for appID := range chunkAppIDs {
		for _, fp := range state.pems.Keys() {
			if _, inChunk := chunkPEMs[fp]; inChunk {
				continue
			}
			cached, ok := state.pems.Get(fp)
			if !ok {
				continue
			}
			pairs = append(pairs, pairCandidate{
				pem: cached.value, appID: appID, companionLoc: cached.location,
			})
		}
	}
	for fp, pemStr := range chunkPEMs {
		state.pems.Add(fp, halfInfo{value: pemStr, location: companionLoc})
	}
	for appID := range chunkAppIDs {
		state.appIDs.Add(appID, halfInfo{value: appID, location: companionLoc})
	}
	state.mu.Unlock()

	for _, p := range pairs {
		results = append(results, makeResult(ctx, p.pem, p.appID, p.companionLoc, "cross-chunk", verify))
	}
	return results, nil
}

func sourceIDFromCtx(ctx context.Context) (sources.SourceID, bool) {
	v := ctx.Value("chunk_source_id")
	if v == nil {
		return 0, false
	}
	sid, ok := v.(sources.SourceID)
	if !ok || sid == 0 {
		return 0, false
	}
	return sid, true
}

func sourceMetadataFromCtx(ctx context.Context) string {
	v := ctx.Value("chunk_source_metadata")
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func makeResult(ctx context.Context, pemStr, appID, companionLoc, pairing string, verify bool) detectors.Result {
	extraData := map[string]string{
		"app_id":         appID,
		"pairing":        pairing,
		"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
	}
	if companionLoc != "" {
		extraData["companion_location"] = companionLoc
	}
	r := detectors.Result{
		DetectorType: detector_typepb.DetectorType_GitHubApp,
		Raw:          []byte(pemStr),
		RawV2:        []byte(appID + ":" + pemStr),
		SecretParts: map[string]string{
			"private_key": pemStr,
			"app_id":      appID,
		},
		ExtraData: extraData,
	}
	if verify {
		verified, extra, vErr := verifyApp(ctx, pemStr, appID)
		if vErr != nil {
			r.SetVerificationError(vErr, pemStr)
		} else {
			r.Verified = verified
			for k, v := range extra {
				r.ExtraData[k] = v
			}
		}
	}
	return r
}

func pemFingerprint(pemStr string) string {
	normalized := strings.Join(strings.Fields(pemStr), "")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func isGitHubAppKeyShape(pemStr string) bool {
	block, _ := pem.Decode([]byte(dedentPEM(pemStr)))
	if block == nil {
		return false
	}
	if block.Type != "RSA PRIVATE KEY" {
		return false
	}
	if _, ok := block.Headers["Proc-Type"]; ok {
		return false
	}
	if _, ok := block.Headers["DEK-Info"]; ok {
		return false
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false
	}
	if len(key.Primes) != 2 {
		return false
	}
	if key.N.BitLen() != 2048 {
		return false
	}
	if key.E != 65537 {
		return false
	}
	for _, p := range key.Primes {
		if p.BitLen() != 1024 {
			return false
		}
	}
	return true
}

func dedentPEM(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, " \t")
	}
	return strings.Join(lines, "\n")
}

func verifyApp(ctx context.Context, pemStr, appID string) (bool, map[string]string, error) {
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(dedentPEM(pemStr)))
	if err != nil {
		return false, nil, nil
	}
	now := time.Now()
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["iat"] = now.Add(-60 * time.Second).Unix()
	claims["exp"] = now.Add(9 * 60 * time.Second).Unix()
	claims["iss"] = appID
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return false, nil, fmt.Errorf("jwt sign: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/app", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenString))
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		var app struct {
			Slug  string `json:"slug"`
			Name  string `json:"name"`
			Owner struct {
				Login string `json:"login"`
				Type  string `json:"type"`
			} `json:"owner"`
			Permissions map[string]string `json:"permissions"`
			Events      []string          `json:"events"`
			CreatedAt   string            `json:"created_at"`
		}
		if err := json.NewDecoder(res.Body).Decode(&app); err != nil {
			return true, nil, nil
		}
		perms := make([]string, 0, len(app.Permissions))
		for k, v := range app.Permissions {
			perms = append(perms, k+"="+v)
		}
		sort.Strings(perms)
		events := append([]string(nil), app.Events...)
		sort.Strings(events)
		return true, map[string]string{
			"app_slug":    app.Slug,
			"app_name":    app.Name,
			"owner_login": app.Owner.Login,
			"owner_type":  app.Owner.Type,
			"permissions": strings.Join(perms, ","),
			"events":      strings.Join(events, ","),
			"created_at":  app.CreatedAt,
		}, nil
	case http.StatusUnauthorized, http.StatusNotFound:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected status %d", res.StatusCode)
	}
}

func (s *Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s *Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GitHubApp
}

func (s *Scanner) Description() string {
	return "GitHub Apps allow you to automate and improve your workflow. GitHub App keys can be used to authenticate and interact with the GitHub API on behalf of the app."
}
