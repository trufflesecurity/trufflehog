package common

import (
	"context"
	"fmt"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
)

type Secret struct{ kv map[string]string }

// fataler is the part of testing.TB that MustGetField needs. It keeps the
// testing package out of this non-test file.
type fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

// MustGetField fails the calling test when the field is missing. A panic here
// would stop every other test in the package.
func (s *Secret) MustGetField(t fataler, name string) string {
	t.Helper()
	val, ok := s.kv[name]
	if !ok {
		t.Fatalf("test secret field %s not found", name)
	}
	return val
}

func GetSecretFromEnv(filename string) (secret *Secret, err error) {
	data, err := godotenv.Read(filename)
	if err != nil {
		return nil, err
	}
	return &Secret{kv: data}, nil
}

func GetTestSecret(ctx context.Context) (secret *Secret, err error) {
	filename := os.Getenv("TEST_SECRET_FILE")
	if len(filename) > 0 {
		return GetSecretFromEnv(filename)
	}

	return GetSecret(ctx, "trufflehog-testing", "test")
}

func GetSecret(ctx context.Context, gcpProject, name string) (secret *Secret, err error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	filename := os.Getenv("TEST_SECRET_FILE")
	if len(filename) > 0 {
		return GetSecretFromEnv(filename)
	}

	parent := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", gcpProject, name)

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, errors.Errorf("failed to create secretmanager client: %v", err)
	}
	defer func() { _ = client.Close() }()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: parent,
	}

	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, errors.Errorf("failed to access secret version: %v", err)
	}

	data, err := godotenv.Unmarshal(string(result.Payload.Data))
	if err != nil {
		return nil, err
	}

	return &Secret{kv: data}, nil
}
