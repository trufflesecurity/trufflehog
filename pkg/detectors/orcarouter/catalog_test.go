package orcarouter

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const catalogFixture = `{
  "data": [
    {
      "id": "openai/gpt-5.5",
      "name": "GPT-5.5",
      "context_length": 400000,
      "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["text"]},
      "supported_endpoint_types": ["openai", "openai-response"]
    },
    {
      "id": "deepseek/deepseek-v4-pro",
      "name": "DeepSeek V4 Pro",
      "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]},
      "supported_endpoint_types": ["openai"]
    },
    {
      "id": "google/gemini-3.5-flash",
      "name": "Gemini 3.5 Flash",
      "architecture": {"input_modalities": ["text", "image", "audio", "video"], "output_modalities": ["text"]},
      "supported_endpoint_types": ["gemini"]
    },
    {
      "id": "openai/text-embedding-3-large",
      "name": "Text Embedding 3 Large",
      "architecture": {"input_modalities": ["text"], "output_modalities": ["embeddings"]},
      "supported_endpoint_types": ["embeddings"]
    },
    {
      "id": "black-forest-labs/flux-1.1-pro",
      "name": "FLUX 1.1 Pro",
      "architecture": {"input_modalities": ["text"], "output_modalities": ["image"]},
      "supported_endpoint_types": ["image-generation"]
    },
    {
      "id": "openai/sora-2",
      "name": "Sora 2",
      "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["video"]},
      "supported_endpoint_types": ["openai-video"]
    },
    {
      "id": "jina/jina-reranker-v2",
      "name": "Jina Reranker v2",
      "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]},
      "supported_endpoint_types": ["jina-rerank"]
    },
    {
      "id": "mystery/model",
      "name": "Mystery",
      "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]},
      "supported_endpoint_types": ["systemone"]
    },
    {
      "id": "noarch/model",
      "name": "No architecture",
      "supported_endpoint_types": ["openai"]
    }
  ]
}`

func fixtureCatalog(t *testing.T) Catalog {
	t.Helper()

	var catalog Catalog
	if err := json.Unmarshal([]byte(catalogFixture), &catalog); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return catalog
}

func modelIDs(models []Model) []string {
	ids := make([]string, 0, len(models))
	for _, model := range models {
		ids = append(ids, model.ID)
	}
	return ids
}

func TestCatalogParsingPreservesVendorNamespace(t *testing.T) {
	catalog := fixtureCatalog(t)

	if len(catalog.Data) != 9 {
		t.Fatalf("expected 9 models, got %d", len(catalog.Data))
	}

	first := catalog.Data[0]
	if first.ID != "openai/gpt-5.5" {
		t.Errorf("expected vendor namespace preserved, got %q", first.ID)
	}
	if first.ContextLength != 400000 {
		t.Errorf("expected context length parsed, got %d", first.ContextLength)
	}
	if !first.SupportsInputModality(ModalityImage) {
		t.Errorf("expected image input modality parsed")
	}
}

func TestCatalogFilterChat(t *testing.T) {
	catalog := fixtureCatalog(t)

	got := modelIDs(catalog.Filter(CapabilityChat))
	want := []string{
		"openai/gpt-5.5",
		"deepseek/deepseek-v4-pro",
		"google/gemini-3.5-flash",
		"noarch/model",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("chat models diff (-want +got):\n%s", diff)
	}
}

func TestCatalogFilterChatNeverIncludesNonTextModels(t *testing.T) {
	catalog := fixtureCatalog(t)

	for _, model := range catalog.Filter(CapabilityChat) {
		if model.Supports(CapabilityEmbedding) ||
			model.Supports(CapabilityImage) ||
			model.Supports(CapabilityVideo) ||
			model.Supports(CapabilityRerank) {
			t.Errorf("model %q is dedicated to a non-chat capability but was offered for chat", model.ID)
		}
	}
}

func TestCatalogFilterMultimodalFailsClosed(t *testing.T) {
	catalog := fixtureCatalog(t)

	tests := []struct {
		name      string
		modality  string
		wantModel []string
	}{
		{
			name:      "image input",
			modality:  ModalityImage,
			wantModel: []string{"openai/gpt-5.5", "google/gemini-3.5-flash"},
		},
		{
			name:      "audio input",
			modality:  ModalityAudio,
			wantModel: []string{"google/gemini-3.5-flash"},
		},
		{
			name:      "video input",
			modality:  ModalityVideo,
			wantModel: []string{"google/gemini-3.5-flash"},
		},
		{
			name:      "unknown modality",
			modality:  "hologram",
			wantModel: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := modelIDs(catalog.Filter(CapabilityChat, test.modality))
			if diff := cmp.Diff(test.wantModel, got); diff != "" {
				t.Errorf("multimodal filter diff (-want +got):\n%s", diff)
			}
		})
	}

	// A chat model that does not publish an architecture must not be treated as
	// multimodal merely because it is chat capable.
	for _, model := range catalog.Filter(CapabilityChat, ModalityImage) {
		if model.ID == "noarch/model" {
			t.Errorf("model without architecture metadata was offered for image input")
		}
	}
}

func TestCatalogFilterDedicatedCapabilities(t *testing.T) {
	catalog := fixtureCatalog(t)

	tests := []struct {
		name       string
		capability Capability
		wantModel  []string
	}{
		{"embedding", CapabilityEmbedding, []string{"openai/text-embedding-3-large"}},
		{"image generation", CapabilityImage, []string{"black-forest-labs/flux-1.1-pro"}},
		{"video generation", CapabilityVideo, []string{"openai/sora-2"}},
		{"rerank", CapabilityRerank, []string{"jina/jina-reranker-v2"}},
		{"unknown capability", Capability("speech"), []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := modelIDs(catalog.Filter(test.capability))
			if diff := cmp.Diff(test.wantModel, got); diff != "" {
				t.Errorf("filter diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCatalogFilterIgnoresNameHeuristics(t *testing.T) {
	// The only model that mentions "image" in its name is a chat model with
	// image input; the image generation model is identified purely by its
	// declared endpoint type.
	catalog := fixtureCatalog(t)

	imageModels := catalog.Filter(CapabilityImage)
	if len(imageModels) != 1 || imageModels[0].ID != "black-forest-labs/flux-1.1-pro" {
		t.Fatalf("expected image capability to come from endpoint metadata, got %v", modelIDs(imageModels))
	}
}

func TestCatalogCounts(t *testing.T) {
	catalog := fixtureCatalog(t)

	want := map[string]int{
		"model_count":            9,
		"chat_model_count":       4,
		"vision_model_count":     2,
		"embedding_model_count":  1,
		"image_generation_count": 1,
		"video_generation_count": 1,
		"rerank_model_count":     1,
	}
	got := catalog.Counts()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("counts diff (-want +got):\n%s", diff)
	}
}
