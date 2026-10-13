package config

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	exampleAWSID     = "AKIAWGXZ9OPDOWUJMZGI"
	exampleSOPSData  = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
	exampleKMSCipher = "AQICAH" + "xYz0123456789AbCdEfGhIjKlMnOpQrStUvWx+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde"
)

func TestEncryptedAWSExample(t *testing.T) {
	cfg, err := Read("../../examples/encrypted_aws.yml")
	require.NoError(t, err)
	require.Len(t, cfg.Detectors, 3)

	byName := map[string]detectors.Detector{}
	for _, d := range cfg.Detectors {
		require.Equal(t, detector_typepb.DetectorType_CustomRegex, d.Type())
		cd, ok := d.(*custom_detectors.CustomRegexWebhook)
		require.True(t, ok)
		results, err := d.FromData(context.Background(), false, []byte("no secrets here"))
		require.NoError(t, err)
		require.Empty(t, results)
		byName[cd.GetName()] = d
	}

	sopsDetector, ok := byName["AWS-SOPS-Encrypted-Secret"]
	require.True(t, ok)
	kmsDetector, ok := byName["AWS-KMS-Encrypted-Secret"]
	require.True(t, ok)
	idDetector, ok := byName["AWS-Access-Key-ID"]
	require.True(t, ok)

	sopsInput := "aws_access_key_id: " + exampleAWSID + "\naws_secret_access_key: ENC[AES256_GCM,data:" + exampleSOPSData + ",iv:abcd,tag:efgh,type:str]\n"
	kmsInput := "aws_access_key_id: " + exampleAWSID + "\naws_secret_access_key: " + exampleKMSCipher + "\n"
	idOnlyInput := "aws_access_key_id: " + exampleAWSID + "\n"

	sopsResults, err := sopsDetector.FromData(context.Background(), false, []byte(sopsInput))
	require.NoError(t, err)
	require.NotEmpty(t, sopsResults)
	require.False(t, sopsResults[0].Verified)
	require.Equal(t, "AWS-SOPS-Encrypted-Secret", sopsResults[0].DetectorName)

	kmsOnSOPS, err := kmsDetector.FromData(context.Background(), false, []byte(sopsInput))
	require.NoError(t, err)
	require.Empty(t, kmsOnSOPS)

	kmsResults, err := kmsDetector.FromData(context.Background(), false, []byte(kmsInput))
	require.NoError(t, err)
	require.NotEmpty(t, kmsResults)
	require.False(t, kmsResults[0].Verified)
	require.Equal(t, "AWS-KMS-Encrypted-Secret", kmsResults[0].DetectorName)

	idResults, err := idDetector.FromData(context.Background(), false, []byte(idOnlyInput))
	require.NoError(t, err)
	require.NotEmpty(t, idResults)
	require.False(t, idResults[0].Verified)
	require.Contains(t, string(idResults[0].Raw), exampleAWSID)

	sopsOnIDOnly, err := sopsDetector.FromData(context.Background(), false, []byte(idOnlyInput))
	require.NoError(t, err)
	require.Empty(t, sopsOnIDOnly)

	require.True(t, strings.HasPrefix(exampleKMSCipher, "AQICAH"))
	require.GreaterOrEqual(t, len(exampleKMSCipher)-len("AQICAH"), 80)
}
