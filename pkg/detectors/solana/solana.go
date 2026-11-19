package solana

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)
var _ detectors.MaxSecretSizeProvider = (*Scanner)(nil)

// CloudEndpoint returns the Solana mainnet JSON-RPC endpoint used for
// verification.
func (Scanner) CloudEndpoint() string { return "https://api.mainnet-beta.solana.com" }

var (
	defaultClient = common.SaneHttpClient()

	// A Solana CLI keypair file (~/.config/solana/id.json, as produced by
	// `solana-keygen new`) is a JSON array of exactly 64 unsigned bytes:
	// the 32-byte Ed25519 seed followed by the 32-byte public key.
	// The file has no keyword to trigger on, so detection is parse-based:
	// find `[`, take the text up to the matching `]`, and accept it only
	// when it parses as exactly 64 integers in [0, 255].
	keypairLen = 64

	// maxKeypairSize bounds the bytes a keypair array may span. A compact
	// array is about 260 bytes; a pretty-printed one (one number per line)
	// is a few hundred more. Anything larger cannot be a keypair file.
	maxKeypairSize = 2048

	// maxCandidates bounds the parse attempts per chunk so a large JSON
	// document full of arrays cannot make detection expensive.
	maxCandidates = 1024
)

// Keywords are used for efficiently pre-filtering chunks.
// A keypair file contains no provider name or other keyword, just numbers
// and commas, so the only usable trigger is the opening bracket of the
// JSON array itself.
func (s Scanner) Keywords() []string {
	return []string{"["}
}

// MaxSecretSize returns the maximum size of a secret that this detector can find.
func (Scanner) MaxSecretSize() int64 { return int64(maxKeypairSize) }

// FromData will find and optionally verify Solana keypair files in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	seen := make(map[string]struct{})
	for _, candidate := range findKeypairCandidates(data) {
		raw := string(candidate)
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}

		keypair, ok := parseKeypair(candidate)
		if !ok {
			continue
		}
		// Bytes 32-63 are the public key. Its base58 encoding is the
		// Solana address used for verification.
		address := base58Encode(keypair[32:])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Solana,
			Raw:          []byte(raw),
			SecretParts: map[string]string{
				"key":        raw,
				"public_key": address,
			},
		}

		if verify {
			client := s.VerificationClient(cmp.Or(s.client, defaultClient))
			var lastErr error
			for _, endpoint := range s.Endpoints() {
				verified, lamports, vErr := verifyKeypair(ctx, client, endpoint, address)
				s1.Verified = verified
				if vErr != nil {
					lastErr = vErr
				}
				if verified {
					lastErr = nil
					s1.ExtraData = map[string]string{
						"public_key": address,
						"lamports":   fmt.Sprintf("%d", lamports),
					}
					break
				}
			}
			s1.SetVerificationError(lastErr, raw)
		}

		results = append(results, s1)
	}

	return results, nil
}

// findKeypairCandidates returns the raw text of every bracketed slice in
// data that could plausibly be a keypair array: short enough to be one,
// and starting with a digit, sign, or whitespace after the bracket.
// Parsing (and the exact 64-integer check) happens in parseKeypair.
func findKeypairCandidates(data []byte) [][]byte {
	var candidates [][]byte
	attempts := 0
	for i := 0; i < len(data) && attempts < maxCandidates; i++ {
		if data[i] != '[' {
			continue
		}
		closeIdx := bytes.IndexByte(data[i:], ']')
		if closeIdx < 0 {
			break
		}
		end := i + closeIdx + 1
		if end-i > maxKeypairSize {
			continue
		}
		attempts++
		candidates = append(candidates, data[i:end])
	}
	return candidates
}

// parseKeypair accepts data only when it is a JSON array of exactly 64
// integers, each in [0, 255]. Anything else (wrong length, out-of-range
// values, floats, nested arrays, non-JSON) is rejected.
func parseKeypair(data []byte) ([]byte, bool) {
	// Reject obvious non-arrays before paying for a JSON parse.
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']' {
		return nil, false
	}

	var values []int
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if err := dec.Decode(&values); err != nil {
		return nil, false
	}
	// A trailing token after the array (for example a second value)
	// means this slice is not a standalone array.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, false
	}
	if len(values) != keypairLen {
		return nil, false
	}

	keypair := make([]byte, keypairLen)
	for i, v := range values {
		if v < 0 || v > 255 {
			return nil, false
		}
		keypair[i] = byte(v)
	}
	return keypair, true
}

// base58Encode encodes bytes with the Bitcoin base58 alphabet, which is
// the alphabet Solana uses for addresses.
func base58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zero bytes: each one becomes a leading '1'.
	zeroes := 0
	for zeroes < len(input) && input[zeroes] == 0 {
		zeroes++
	}

	// Convert base-256 to base-58. size is an upper bound on the encoded
	// length: log(256)/log(58) is about 1.37.
	size := (len(input)-zeroes)*138/100 + 1
	encoded := make([]byte, size)
	var length int
	for _, b := range input[zeroes:] {
		carry := int(b)
		for j := size - 1; j >= size-length; j-- {
			carry += 256 * int(encoded[j])
			encoded[j] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			length++
			encoded[size-length] = byte(carry % 58)
			carry /= 58
		}
	}

	var out strings.Builder
	out.Grow(zeroes + length)
	for i := 0; i < zeroes; i++ {
		out.WriteByte(alphabet[0])
	}
	for _, d := range encoded[size-length:] {
		out.WriteByte(alphabet[d])
	}
	return out.String()
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result *struct {
		Value *struct {
			Lamports uint64 `json:"lamports"`
		} `json:"value"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// verifyKeypair calls getAccountInfo for the address derived from the
// keypair. An account that exists with non-zero lamports verifies the
// keypair. A missing account determinately does not verify. Anything else
// (RPC error, unexpected status or body, transport failure) is
// indeterminate and returns a non-nil error.
func verifyKeypair(ctx context.Context, client *http.Client, endpoint, address string) (bool, uint64, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getAccountInfo",
		Params:  []any{address, map[string]string{"encoding": "base64"}},
	})
	if err != nil {
		return false, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	var rpcRes rpcResponse
	if err := json.NewDecoder(res.Body).Decode(&rpcRes); err != nil {
		return false, 0, err
	}
	if rpcRes.Error != nil {
		return false, 0, fmt.Errorf("solana RPC error %d: %s", rpcRes.Error.Code, rpcRes.Error.Message)
	}
	if rpcRes.Result == nil || rpcRes.Result.Value == nil {
		// Determinately invalid: the account does not exist on chain.
		return false, 0, nil
	}
	if rpcRes.Result.Value.Lamports == 0 {
		return false, 0, nil
	}
	return true, rpcRes.Result.Value.Lamports, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Solana
}

func (s Scanner) Description() string {
	return "Solana is a high-performance blockchain. Solana CLI keypair files store a raw Ed25519 keypair as a JSON array of 64 bytes; possession of the file grants full control of the associated wallet and all on-chain assets."
}
