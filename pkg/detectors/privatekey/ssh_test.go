package privatekey

import (
	"context"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"golang.org/x/crypto/ssh"
)

func TestFirstResponseFromSSH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretGitHub := testSecrets.MustGetField("PRIVATEKEY_GITHUB")

	parsedKey, err := ssh.ParseRawPrivateKey([]byte(normalize(secretGitHub)))
	if err != nil {
		t.Fatalf("could not parse test secret: %s", err)
	}

	output, err := firstResponseFromSSH(parsedKey, "git", "github.com:22")
	if err != nil {
		t.Fail()
	}

	if len(output) == 0 {
		t.Fail()
	}
}
