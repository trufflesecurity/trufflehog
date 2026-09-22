package sailpointidentityiq

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestScanner(t *testing.T) {
	tests := []struct {
		secret   string
		password string
	}{
		{"1:ACP:AAECAwQFBgcICQoLDA0OD28VaY9z3ztl+tPDTO7nx1Q=", "I_love_DIAN"},
		{"1:ACP:EBESExQVFhcYGRobHB0eHy8zFnIMh7gnPxd/mDNj5Kc=", "soleil123!"},
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
}
