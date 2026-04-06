package ocr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/configpb"
)

// CustomHTTPProvider extracts text from a user-defined HTTP OCR endpoint.
// Authentication, request body, and response parsing are all configurable.
type CustomHTTPProvider struct {
	cfg        *configpb.CustomOCRConfig
	bodyTmpl   *template.Template
	httpClient *http.Client
}

// templateData holds the variables available inside body_template.
type templateData struct {
	Base64Image string
	MimeType    string
}

// NewCustomHTTPProvider constructs a CustomHTTPProvider from the proto config.
// It validates required fields and pre-compiles the body template.
func NewCustomHTTPProvider(cfg *configpb.CustomOCRConfig) (*CustomHTTPProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("custom ocr: config must not be nil")
	}
	if cfg.GetEndpoint() == "" {
		return nil, fmt.Errorf("custom ocr: endpoint must not be empty")
	}

	reqCfg := cfg.GetRequest()
	rawTmpl := ""
	if reqCfg != nil {
		rawTmpl = reqCfg.GetBodyTemplate()
	}
	if rawTmpl == "" {
		return nil, fmt.Errorf("custom ocr: request.body_template must not be empty")
	}

	respCfg := cfg.GetResponse()
	if respCfg == nil || respCfg.GetTextPath() == "" {
		return nil, fmt.Errorf("custom ocr: response.text_path must not be empty")
	}

	tmpl, err := template.New("body").Parse(rawTmpl)
	if err != nil {
		return nil, fmt.Errorf("custom ocr: parsing body_template: %w", err)
	}

	return &CustomHTTPProvider{
		cfg:        cfg,
		bodyTmpl:   tmpl,
		httpClient: &http.Client{},
	}, nil
}

// ExtractText sends imageData to the configured endpoint and returns the extracted text.
func (p *CustomHTTPProvider) ExtractText(ctx context.Context, imageData []byte) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(imageData)

	var bodyBuf bytes.Buffer
	if err := p.bodyTmpl.Execute(&bodyBuf, templateData{
		Base64Image: encoded,
		MimeType:    "image/png",
	}); err != nil {
		return "", fmt.Errorf("custom ocr: rendering body template: %w", err)
	}

	endpoint := p.buildURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &bodyBuf)
	if err != nil {
		return "", fmt.Errorf("custom ocr: creating request: %w", err)
	}

	contentType := "application/json"
	if reqCfg := p.cfg.GetRequest(); reqCfg != nil && reqCfg.GetContentType() != "" {
		contentType = reqCfg.GetContentType()
	}
	req.Header.Set("Content-Type", contentType)

	if err := p.applyAuth(req); err != nil {
		return "", err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("custom ocr: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("custom ocr: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("custom ocr: unexpected status %d: %s", resp.StatusCode, body)
	}

	return p.extractText(body)
}

// buildURL appends a query-param API key when auth.type is "api_key_query".
func (p *CustomHTTPProvider) buildURL() string {
	auth := p.cfg.GetAuth()
	if auth == nil || auth.GetType() != "api_key_query" {
		return p.cfg.GetEndpoint()
	}
	u, err := url.Parse(p.cfg.GetEndpoint())
	if err != nil {
		return p.cfg.GetEndpoint()
	}
	q := u.Query()
	q.Set(auth.GetParamName(), ExpandEnv(auth.GetValue()))
	u.RawQuery = q.Encode()
	return u.String()
}

// applyAuth sets authentication headers/credentials on req based on auth.type.
func (p *CustomHTTPProvider) applyAuth(req *http.Request) error {
	auth := p.cfg.GetAuth()
	if auth == nil {
		return nil
	}
	switch auth.GetType() {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+ExpandEnv(auth.GetValue()))
	case "header":
		if auth.GetHeaderName() == "" {
			return fmt.Errorf("custom ocr: auth.header_name must not be empty when type is \"header\"")
		}
		req.Header.Set(auth.GetHeaderName(), ExpandEnv(auth.GetValue()))
	case "api_key_query":
		// Already handled in buildURL; nothing to do on the request itself.
	case "basic":
		req.SetBasicAuth(ExpandEnv(auth.GetUsername()), ExpandEnv(auth.GetPassword()))
	case "":
		// No auth configured.
	default:
		return fmt.Errorf("custom ocr: unknown auth type %q (want: bearer, header, api_key_query, basic)", auth.GetType())
	}
	return nil
}

// extractText navigates the dot-separated text_path into the parsed JSON response
// and returns the string value at that location.
//
// Path segments that are purely numeric are treated as array indices.
// Example: "choices.0.message.content" → response["choices"][0]["message"]["content"]
func (p *CustomHTTPProvider) extractText(body []byte) (string, error) {
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("custom ocr: parsing JSON response: %w", err)
	}

	textPath := p.cfg.GetResponse().GetTextPath()
	segments := strings.Split(textPath, ".")
	current := parsed
	for _, seg := range segments {
		switch node := current.(type) {
		case map[string]interface{}:
			val, ok := node[seg]
			if !ok {
				return "", fmt.Errorf("custom ocr: key %q not found in response at path %q", seg, textPath)
			}
			current = val
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return "", fmt.Errorf("custom ocr: segment %q is not a valid array index in path %q", seg, textPath)
			}
			if idx < 0 || idx >= len(node) {
				return "", fmt.Errorf("custom ocr: index %d out of bounds (len=%d) in path %q", idx, len(node), textPath)
			}
			current = node[idx]
		default:
			return "", fmt.Errorf("custom ocr: cannot traverse segment %q in path %q: not an object or array", seg, textPath)
		}
	}

	text, ok := current.(string)
	if !ok {
		return "", fmt.Errorf("custom ocr: value at path %q is not a string (got %T)", textPath, current)
	}
	return text, nil
}
