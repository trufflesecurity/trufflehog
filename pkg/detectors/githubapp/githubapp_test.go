package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func newTestPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func ctxWithSource(sid sources.SourceID, metadata string) context.Context {
	ctx := context.WithValue(context.Background(), "chunk_source_id", sid)
	return context.WithValue(ctx, "chunk_source_metadata", metadata)
}

func TestGithubApp_Pattern(t *testing.T) {
	pemStr := newTestPEM(t)
	appID := "456731"
	input := fmt.Sprintf("github_app_id: %s\ngithub_app_private_key: |\n%s", appID, pemStr)

	d := &Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	if matched := core.FindDetectorMatches([]byte(input)); len(matched) == 0 {
		t.Fatalf("keywords %v not matched in input", d.Keywords())
	}

	results, err := d.FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("FromData err = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	got := results[0]
	want := appID + ":" + strings.TrimSpace(pemStr)
	if diff := cmp.Diff(want, string(got.RawV2)); diff != "" {
		t.Errorf("RawV2 mismatch (-want +got):\n%s", diff)
	}
	if got.SecretParts["app_id"] != appID {
		t.Errorf("SecretParts[app_id] = %q, want %q", got.SecretParts["app_id"], appID)
	}
	if !strings.Contains(got.SecretParts["private_key"], "RSA PRIVATE KEY") {
		t.Errorf("SecretParts[private_key] missing PEM header")
	}
	if got.ExtraData["pairing"] != "in-chunk" {
		t.Errorf("ExtraData[pairing] = %q, want %q", got.ExtraData["pairing"], "in-chunk")
	}
}

func TestGithubApp_RejectsNonAppShapeKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	input := fmt.Sprintf("github_app_id: 1234567\nkey:\n%s", pkcs8PEM)

	results, err := (&Scanner{}).FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("FromData err = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for PKCS#8 key, got %d", len(results))
	}
}

func TestGithubApp_NoSourceID_NoCrossChunk(t *testing.T) {
	s := &Scanner{}
	pemStr := newTestPEM(t)

	r1, err := s.FromData(context.Background(), false, []byte("private_key: "+pemStr))
	if err != nil {
		t.Fatalf("FromData #1 err = %v", err)
	}
	if len(r1) != 0 {
		t.Errorf("PEM-only chunk produced %d results, want 0", len(r1))
	}

	r2, err := s.FromData(context.Background(), false, []byte("github_app_id: 3787015"))
	if err != nil {
		t.Fatalf("FromData #2 err = %v", err)
	}
	if len(r2) != 0 {
		t.Errorf("App-ID-only chunk (no source) produced %d results, want 0", len(r2))
	}
}

func TestGithubApp_CrossChunk_SameSource(t *testing.T) {
	s := &Scanner{}
	pemStr := newTestPEM(t)
	appID := "3787015"

	ctx1 := ctxWithSource(42, "git://repo/path/key.pem:line 1")
	r1, err := s.FromData(ctx1, false, []byte("private_key: "+pemStr))
	if err != nil {
		t.Fatalf("FromData #1 err = %v", err)
	}
	if len(r1) != 0 {
		t.Errorf("PEM-only chunk produced %d results, want 0", len(r1))
	}

	ctx2 := ctxWithSource(42, "git://repo/path/values.yaml:line 7")
	r2, err := s.FromData(ctx2, false, []byte("github_app_id: "+appID))
	if err != nil {
		t.Fatalf("FromData #2 err = %v", err)
	}
	if len(r2) != 1 {
		t.Fatalf("App-ID chunk produced %d results, want 1", len(r2))
	}
	got := r2[0]
	if got.ExtraData["pairing"] != "cross-chunk" {
		t.Errorf("ExtraData[pairing] = %q, want %q", got.ExtraData["pairing"], "cross-chunk")
	}
	if got.ExtraData["app_id"] != appID {
		t.Errorf("ExtraData[app_id] = %q, want %q", got.ExtraData["app_id"], appID)
	}
	if got.ExtraData["companion_location"] != "git://repo/path/key.pem:line 1" {
		t.Errorf("ExtraData[companion_location] = %q, want PEM chunk location",
			got.ExtraData["companion_location"])
	}
}

func TestGithubApp_CrossChunk_DifferentSourcesDoNotPair(t *testing.T) {
	s := &Scanner{}
	pemStr := newTestPEM(t)

	r1, err := s.FromData(
		ctxWithSource(1, "git://orgA/repo/key.pem"),
		false,
		[]byte("private_key: "+pemStr),
	)
	if err != nil {
		t.Fatalf("FromData #1 err = %v", err)
	}
	if len(r1) != 0 {
		t.Errorf("PEM in source A produced %d results, want 0", len(r1))
	}

	r2, err := s.FromData(
		ctxWithSource(2, "git://orgB/repo/values.yaml"),
		false,
		[]byte("github_app_id: 9876543"),
	)
	if err != nil {
		t.Fatalf("FromData #2 err = %v", err)
	}
	if len(r2) != 0 {
		t.Errorf("App ID in source B produced %d results, want 0 (different sources must not pair)", len(r2))
	}
}

func TestGithubApp_DedupesWithinChunk(t *testing.T) {
	pemStr := newTestPEM(t)
	appID := "1234567"
	input := fmt.Sprintf(
		"github_app_id: %s\nkey: %s\ngithub_app_id: %s\nkey: %s",
		appID, pemStr, appID, pemStr,
	)

	results, err := (&Scanner{}).FromData(context.Background(), false, []byte(input))
	if err != nil {
		t.Fatalf("FromData err = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 deduped result, got %d", len(results))
	}
}

func TestGithubApp_CrossChunk_BothHalvesInSameChunkLater(t *testing.T) {
	s := &Scanner{}
	pemStr := newTestPEM(t)
	appID := "5555555"
	ctx := ctxWithSource(7, "git://repo/file1.pem")

	if _, err := s.FromData(ctx, false, []byte("private_key: "+pemStr)); err != nil {
		t.Fatalf("FromData #1 err = %v", err)
	}

	r, err := s.FromData(ctx, false, []byte(fmt.Sprintf("github_app_id: %s\n%s", appID, pemStr)))
	if err != nil {
		t.Fatalf("FromData #2 err = %v", err)
	}
	if len(r) != 1 {
		t.Errorf("expected 1 result (in-chunk only), got %d", len(r))
	}
	if r[0].ExtraData["pairing"] != "in-chunk" {
		t.Errorf("ExtraData[pairing] = %q, want %q", r[0].ExtraData["pairing"], "in-chunk")
	}
}
