package orcarouter

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOrcaRouter_Live exercises the production verification path against the
// real OrcaRouter API when a key is supplied by the environment. It is skipped
// in normal unit test runs so the package stays hermetic.
func TestOrcaRouter_Live(t *testing.T) {
	key := os.Getenv("ORCAROUTER_API_KEY")
	if key == "" {
		t.Skip("ORCAROUTER_API_KEY is not set")
	}
	if !strings.HasPrefix(key, keyPrefix) {
		t.Fatalf("ORCAROUTER_API_KEY does not use the documented %q prefix", keyPrefix)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	scanner := Scanner{}
	results, err := scanner.FromData(ctx, true, []byte("ORCAROUTER_API_KEY="+key))
	if err != nil {
		t.Fatalf("live verification returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 live result, got %d", len(results))
	}

	result := results[0]
	if !result.Verified {
		t.Fatalf("the supplied OrcaRouter key did not verify")
	}

	modelCount, err := strconv.Atoi(result.ExtraData["model_count"])
	if err != nil || modelCount == 0 {
		t.Fatalf("expected a non-empty live model catalog, got model_count=%q", result.ExtraData["model_count"])
	}
	chatCount, err := strconv.Atoi(result.ExtraData["chat_model_count"])
	if err != nil || chatCount == 0 {
		t.Fatalf("expected live chat models, got chat_model_count=%q", result.ExtraData["chat_model_count"])
	}

	t.Logf("live catalog: %d models, %d chat capable", modelCount, chatCount)
}
