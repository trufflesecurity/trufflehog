//go:build detectors
// +build detectors

package privatekey

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

func TestFirstResponseFromSSH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretGitHub := testSecrets.MustGetField("PRIVATEKEY_GITHUB")

	parsedKey, err := ssh.ParseRawPrivateKey([]byte(Normalize(secretGitHub)))
	if err != nil {
		t.Fatalf("could not parse test secret: %s", err)
	}

	output, err := firstResponseFromSSH(ctx, parsedKey, "git", "github.com:22")
	if err != nil {
		t.Fail()
	}

	if len(output) == 0 {
		t.Fail()
	}
}
