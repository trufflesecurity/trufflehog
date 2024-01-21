package s3

import (
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// NOTE: These are non-table driven tests because you can't set environment variables in a parallel subtest.

func TestSourceGetChunks(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	s := Source{}
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    s3key,
				Secret: s3secret,
			},
		},
		Buckets: []string{"truffletestbucket-s3-tests"},
	}
	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "gets chunks", 0, 0, true, conn, 8)
	if err != nil {
		t.Errorf("Source.Init() error = %v", err)
		return
	}

	chunksCh := make(chan *sources.Chunk)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = s.Chunks(ctx, chunksCh)
		if err != nil {
			t.Errorf("Source.Chunks() error = %v", err)
			os.Exit(1)
		}
	}()

	gotChunk := <-chunksCh
	wantChunkData := `W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lkID0gQUtJQTM1T0hYMkRTT1pHNjQ3TkgKYXdzX3NlY3JldF9hY2Nlc3Nfa2V5ID0gUXk5OVMrWkIvQ1dsRk50eFBBaWQ3Z0d6dnNyWGhCQjd1ckFDQUxwWgpvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`
	wantData, _ := base64.StdEncoding.DecodeString(wantChunkData)

	if diff := pretty.Compare(gotChunk.Data, wantData); diff != "" {
		t.Errorf("Source.Chunks() diff: (-got +want)\n%s", diff)
	}

	wg.Wait()
	assert.Equal(t, "", s.GetProgress().EncodedResumeInfo)
	assert.Equal(t, int64(100), s.GetProgress().PercentComplete)
}

func TestSourceGetChunksAfterAssumingRole(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	os.Setenv("AWS_ACCESS_KEY_ID", s3key)
	os.Setenv("AWS_SECRET_ACCESS_KEY", s3secret)
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")

	s := Source{}
	connection := &sourcespb.S3{
		Roles: []string{"arn:aws:iam::619888638459:role/s3-test-assume-role"},
	}
	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "gets chunks after assuming role", 0, 0, true, conn, 8)
	if err != nil {
		t.Errorf("Source.Init() error = %v", err)
		return
	}

	chunksCh := make(chan *sources.Chunk)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = s.Chunks(ctx, chunksCh)
		if err != nil {
			t.Errorf("Source.Chunks() error = %v", err)
			os.Exit(1)
		}
	}()

	gotChunk := <-chunksCh
	wantChunkData := `W2RlZmF1bHRdCmF3c19zZWNyZXRfYWNjZXNzX2tleSA9IFF5OTlTK1pCL0NXbEZOdHhQQWlkN2dHenZzclhoQkI3dXJBQ0FMcFoKYXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMzVPSFgyRFNPWkc2NDdOSApvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`
	wantData, _ := base64.StdEncoding.DecodeString(wantChunkData)

	if diff := pretty.Compare(gotChunk.Data, wantData); diff != "" {
		t.Errorf("Source.Chunks() diff: (-got +want)\n%s", diff)
	}

	wg.Wait()
	assert.Equal(t, "", s.GetProgress().EncodedResumeInfo)
	assert.Equal(t, int64(100), s.GetProgress().PercentComplete)
}
