package common

import (
	"context"
	"fmt"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

type Secret struct{ kv map[string]string }

func (s *Secret) MustGetField(name string) string {
	val, ok := s.kv[name]
	if !ok {
		panic(errors.Errorf("field %s not found", name))
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
	defer client.Close()

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
