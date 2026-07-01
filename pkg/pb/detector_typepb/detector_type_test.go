package detector_typepb

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestDetectorTypeDescriptorIncludesSeedPhraseTypes(t *testing.T) {
	tests := []struct {
		name string
		typ  DetectorType
		num  protoreflect.EnumNumber
	}{
		{
			name: "BIP39SeedPhrase",
			typ:  DetectorType_BIP39SeedPhrase,
			num:  1056,
		},
		{
			name: "MoneroSeedPhrase",
			typ:  DetectorType_MoneroSeedPhrase,
			num:  1057,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if value := tt.typ.Descriptor().Values().ByNumber(tt.num); value == nil {
				t.Fatalf("DetectorType descriptor missing enum value %d", tt.num)
			}
		})
	}
}
