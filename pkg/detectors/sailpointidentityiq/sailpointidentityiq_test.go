package sailpointidentityiq

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestScanner(t *testing.T) {
	tests := []struct {
		secret   string
		password string
	}{
		{"1:ACP:AAECAwQFBgcICQoLDA0OD28VaY9z3ztl+tPDTO7nx1Q=", "I_love_DIAN"},
		{"1:ACP:EBESExQVFhcYGRobHB0eHy8zFnIMh7gnPxd/mDNj5Kc=", "soleil123!"},
		{"1:ACP:ICEiIyQlJicoKSorLC0uL1nYtInDwq+Wq0gJdCh3IvQiA11Mq5383fRCvulmHnoj", "12345678901234567"},
	}

	for _, test := range tests {
		t.Run(test.password, func(t *testing.T) {
			results, err := (Scanner{}).FromData(context.Background(), true, []byte("password="+test.secret))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.False(t, results[0].Verified, "decryption does not prove that a credential is active")
			require.Equal(t, test.password, string(results[0].Raw))
			require.Equal(t, map[string]string{"key": test.password}, results[0].SecretParts)
		})
	}
}

func TestScannerHandlesDelimitersAndUnpaddedSecrets(t *testing.T) {
	const secret = "1:ACP:ICEiIyQlJicoKSorLC0uL1nYtInDwq+Wq0gJdCh3IvQiA11Mq5383fRCvulmHnoj"

	for _, input := range []string{secret + "\n", `"` + secret + `"`, secret + "followingText\""} {
		results, err := (Scanner{}).FromData(context.Background(), false, []byte(input))
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, "12345678901234567", string(results[0].Raw))
	}
}

func TestScannerRejectsInvalidCiphertext(t *testing.T) {
	for _, input := range []string{
		"1:ACP:not-base64",
		"1:ACP:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"1:ACP:U9o/5LepsscL1gr60zLNFUIi6g0Z/GDQi5J/c9VNudo=", // Invalid UTF-8 plaintext.
	} {
		results, err := (Scanner{}).FromData(context.Background(), true, []byte(input))
		require.NoError(t, err)
		require.Empty(t, results)
	}
}

func TestScannerMetadata(t *testing.T) {
	scanner := Scanner{}
	require.Equal(t, []string{"1:ACP:"}, scanner.Keywords())
	require.Equal(t, detector_typepb.DetectorType_SailPointIdentityIQ, scanner.Type())
	require.EqualValues(t, 5006, scanner.MaxSecretSize())

	isFalsePositive, _ := detectors.GetFalsePositiveCheck(scanner)(detectors.Result{Raw: []byte("root-password")})
	require.False(t, isFalsePositive)
}
