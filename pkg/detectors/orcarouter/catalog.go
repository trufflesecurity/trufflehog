package orcarouter

import "strings"

// Capability identifies a class of model that an OrcaRouter API key can call.
// OrcaRouter exposes one OpenAI-compatible endpoint in front of many upstream
// vendors, so the catalog is the only authoritative source of what a key can
// reach. Every filter below is driven by the catalog metadata returned by
// GET /v1/models; nothing is inferred from a model's name.
type Capability string

const (
	CapabilityChat      Capability = "chat"
	CapabilityEmbedding Capability = "embedding"
	CapabilityImage     Capability = "image"
	CapabilityVideo     Capability = "video"
	CapabilityRerank    Capability = "rerank"
)

// Input modalities reported by the catalog's architecture.input_modalities.
const (
	ModalityText  = "text"
	ModalityImage = "image"
	ModalityAudio = "audio"
	ModalityVideo = "video"
)

// endpointTypes maps each capability to the supported_endpoint_types values
// that prove it. A model is only offered for a capability when its metadata
// names one of these endpoint types explicitly.
var endpointTypes = map[Capability][]string{
	// Text chat and agent traffic. OrcaRouter accepts the OpenAI, Anthropic,
	// Gemini and OpenAI Responses request shapes on the same origin.
	CapabilityChat: {"openai", "anthropic", "gemini", "openai-response"},
	// Embeddings use the OpenAI embeddings shape.
	CapabilityEmbedding: {"embeddings"},
	CapabilityImage:     {"image-generation"},
	CapabilityVideo:     {"openai-video"},
	CapabilityRerank:    {"jina-rerank"},
}

// Catalog is the subset of GET /v1/models that is relevant for capability
// selection. Vendor namespaces are preserved verbatim in Model.ID.
type Catalog struct {
	Data []Model `json:"data"`
}

// Model is a single catalog entry.
type Model struct {
	ID                     string       `json:"id"`
	Name                   string       `json:"name"`
	ContextLength          int          `json:"context_length"`
	Architecture           Architecture `json:"architecture"`
	SupportedEndpointTypes []string     `json:"supported_endpoint_types"`
}

// Architecture describes what a model accepts and produces. Modalities are
// only trustworthy when the catalog states them; an empty list means unknown
// and is treated as unsupported (fail closed).
type Architecture struct {
	InputModalities  []string `json:"input_modalities"`
	OutputModalities []string `json:"output_modalities"`
}

// SupportsEndpointType reports whether the model declares any of want.
func (m Model) SupportsEndpointType(want ...string) bool {
	for _, declared := range m.SupportedEndpointTypes {
		for _, candidate := range want {
			if strings.EqualFold(strings.TrimSpace(declared), candidate) {
				return true
			}
		}
	}
	return false
}

// SupportsInputModality reports whether the catalog explicitly lists modality
// as an accepted input. Unknown modalities fail closed.
func (m Model) SupportsInputModality(modality string) bool {
	for _, declared := range m.Architecture.InputModalities {
		if strings.EqualFold(strings.TrimSpace(declared), modality) {
			return true
		}
	}
	return false
}

// Supports reports whether the model advertises the given capability.
func (m Model) Supports(capability Capability) bool {
	want, ok := endpointTypes[capability]
	if !ok {
		return false
	}
	return m.SupportsEndpointType(want...)
}

// Filter returns the catalog entries that can serve capability, in catalog
// order. For chat, every entry in requiredInputModalities must be explicitly
// declared by the model, so multimodal pickers never receive a text-only model
// and a missing architecture cannot be treated as compatible.
func (c Catalog) Filter(capability Capability, requiredInputModalities ...string) []Model {
	out := make([]Model, 0, len(c.Data))
	for _, model := range c.Data {
		if !model.Supports(capability) {
			continue
		}
		if capability != CapabilityChat {
			out = append(out, model)
			continue
		}
		compatible := true
		for _, modality := range requiredInputModalities {
			if !model.SupportsInputModality(modality) {
				compatible = false
				break
			}
		}
		if compatible {
			out = append(out, model)
		}
	}
	return out
}

// Counts summarises a catalog by capability. It is used to report what the
// verified key can actually reach without disclosing any credential material.
func (c Catalog) Counts() map[string]int {
	return map[string]int{
		"model_count":            len(c.Data),
		"chat_model_count":       len(c.Filter(CapabilityChat)),
		"vision_model_count":     len(c.Filter(CapabilityChat, ModalityImage)),
		"embedding_model_count":  len(c.Filter(CapabilityEmbedding)),
		"image_generation_count": len(c.Filter(CapabilityImage)),
		"video_generation_count": len(c.Filter(CapabilityVideo)),
		"rerank_model_count":     len(c.Filter(CapabilityRerank)),
	}
}
