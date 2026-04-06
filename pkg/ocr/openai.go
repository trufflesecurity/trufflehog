package ocr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const openAIEndpoint = "https://api.openai.com/v1/chat/completions"

// ocrPrompt instructs the model to return only the visible text, verbatim.
const ocrPrompt = "Extract all text visible in this image exactly as it appears, preserving formatting. Output only the extracted text with no commentary."

// OpenAIProvider extracts text using the OpenAI chat completions vision API.
type OpenAIProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewOpenAIProvider creates an OpenAIProvider. model defaults to "gpt-4o" if empty.
func NewOpenAIProvider(apiKey, model string) *OpenAIProvider {
	if model == "" {
		model = "gpt-4o"
	}
	return &OpenAIProvider{
		apiKey:     apiKey,
		model:      model,
		httpClient: &http.Client{},
	}
}

// ExtractText sends imageData to the OpenAI vision API and returns the extracted text.
func (p *OpenAIProvider) ExtractText(ctx context.Context, imageData []byte) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(imageData)
	dataURL := fmt.Sprintf("data:image/png;base64,%s", encoded)

	reqBody, err := json.Marshal(map[string]interface{}{
		"model": p.model,
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{"type": "text", "text": ocrPrompt},
					{"type": "image_url", "image_url": map[string]string{"url": dataURL}},
				},
			},
		},
		"max_tokens": 4096,
	})
	if err != nil {
		return "", fmt.Errorf("openai ocr: marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIEndpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("openai ocr: creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai ocr: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("openai ocr: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai ocr: unexpected status %d: %s", resp.StatusCode, body)
	}

	// Response shape: {"choices": [{"message": {"content": "..."}}]}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("openai ocr: parsing response: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("openai ocr: API error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", nil
	}
	return result.Choices[0].Message.Content, nil
}
