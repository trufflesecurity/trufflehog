package ocr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/configpb"
)

const (
	googleVisionEndpoint = "https://vision.googleapis.com/v1/images:annotate"
	googleVisionScope    = "https://www.googleapis.com/auth/cloud-vision"
)

// GoogleProvider extracts text using the Google Cloud Vision TEXT_DETECTION API.
type GoogleProvider struct {
	apiKey     string // non-empty when using API key auth
	httpClient *http.Client
}

// NewGoogleProvider constructs a GoogleProvider from the proto config.
func NewGoogleProvider(cfg *configpb.GoogleOCRConfig) (*GoogleProvider, error) {
	switch auth := cfg.GetAuth().(type) {

	case *configpb.GoogleOCRConfig_CredentialsFile:
		path := ExpandEnv(auth.CredentialsFile)
		if path == "" {
			return nil, fmt.Errorf("google ocr: credentials_file must not be empty")
		}
		jsonKey, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("google ocr: reading credentials file %q: %w", path, err)
		}
		creds, err := google.CredentialsFromJSON(context.Background(), jsonKey, googleVisionScope)
		if err != nil {
			return nil, fmt.Errorf("google ocr: parsing service account credentials: %w", err)
		}
		return &GoogleProvider{
			httpClient: oauth2.NewClient(context.Background(), creds.TokenSource),
		}, nil

	case *configpb.GoogleOCRConfig_ApiKey:
		apiKey := ExpandEnv(auth.ApiKey)
		if apiKey == "" {
			return nil, fmt.Errorf("google ocr: api_key must not be empty")
		}
		return &GoogleProvider{
			apiKey:     apiKey,
			httpClient: &http.Client{},
		}, nil

	default:
		return nil, fmt.Errorf("google ocr: one of credentials_file or api_key must be set")
	}
}

// ExtractText sends imageData to the Google Cloud Vision API and returns the detected text.
func (p *GoogleProvider) ExtractText(ctx context.Context, imageData []byte) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(imageData)

	reqBody, err := json.Marshal(map[string]interface{}{
		"requests": []map[string]interface{}{
			{
				"image": map[string]string{"content": encoded},
				"features": []map[string]interface{}{
					{"type": "TEXT_DETECTION"},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("google ocr: marshaling request: %w", err)
	}

	url := googleVisionEndpoint
	if p.apiKey != "" {
		url = fmt.Sprintf("%s?key=%s", googleVisionEndpoint, p.apiKey)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("google ocr: creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("google ocr: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("google ocr: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google ocr: unexpected status %d: %s", resp.StatusCode, body)
	}

	// Response shape: {"responses": [{"fullTextAnnotation": {"text": "..."}}]}
	var result struct {
		Responses []struct {
			FullTextAnnotation struct {
				Text string `json:"text"`
			} `json:"fullTextAnnotation"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("google ocr: parsing response: %w", err)
	}
	if len(result.Responses) == 0 {
		return "", nil
	}
	if result.Responses[0].Error != nil {
		return "", fmt.Errorf("google ocr: API error: %s", result.Responses[0].Error.Message)
	}
	return result.Responses[0].FullTextAnnotation.Text, nil
}
