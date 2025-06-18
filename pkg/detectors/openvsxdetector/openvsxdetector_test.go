package openvsxdetector

import (
	"context"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestOpenVSXDetector_FromData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testCases := []struct {
		description string
		data        string
		expected    []detectors.Result
	}{
		{
			description: "VSX GUID",
			data:        "VSX Token: 12345678-abcd-1234-abcd-1234567890ab",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("12345678-abcd-1234-abcd-1234567890ab"),
					RawV2:        []byte("12345678-abcd-1234-abcd-1234567890ab"),
					Redacted:     "12345678-abcd-1234-abcd-1234567890ab",
				},
			},
		},
		{
			description: "VSIX GUID",
			data:        "VSIX EXTENSION ID: 98765432-dcba-4321-dcba-ba0987654321",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("98765432-dcba-4321-dcba-ba0987654321"),
					RawV2:        []byte("98765432-dcba-4321-dcba-ba0987654321"),
					Redacted:     "98765432-dcba-4321-dcba-ba0987654321",
				},
			},
		},
		{
			description: "OpenVSX GUID",
			data:        "OPENVSX PUBLISHER ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
					RawV2:        []byte("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
					Redacted:     "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				},
			},
		},
		{
			description: "npx ovsx publish with -p flag",
			data:        "npx ovsx publish test.vsix -p 5248a297-bd54-433d-9216-7abe57ecd5d0",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					RawV2:        []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					Redacted:     "5248a297-bd54-433d-9216-7abe57ecd5d0",
				},
			},
		},
		{
			description: "OVSX_ACCESS_TOKEN environment variable",
			data:        "OVSX_ACCESS_TOKEN=5248a297-bd54-433d-9216-7abe57ecd5d0",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					RawV2:        []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					Redacted:     "5248a297-bd54-433d-9216-7abe57ecd5d0",
				},
			},
		},
		{
			description: "ovsx publish with -p flag",
			data:        "ovsx publish test.vsix -p 5248a297-bd54-433d-9216-7abe57ecd5d0",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					RawV2:        []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					Redacted:     "5248a297-bd54-433d-9216-7abe57ecd5d0",
				},
			},
		},
		{
			description: "OVSX_PAT environment variable",
			data:        "OVSX_PAT=5248a297-bd54-433d-9216-7abe57ecd5d0",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					RawV2:        []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					Redacted:     "5248a297-bd54-433d-9216-7abe57ecd5d0",
				},
			},
		},
		{
			description: "OVSX_KEY environment variable",
			data:        "OVSX_KEY=5248a297-bd54-433d-9216-7abe57ecd5d0",
			expected: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_OpenVSX,
					Raw:          []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					RawV2:        []byte("5248a297-bd54-433d-9216-7abe57ecd5d0"),
					Redacted:     "5248a297-bd54-433d-9216-7abe57ecd5d0",
				},
			},
		},
		{
			description: "GUID without VSX prefix",
			data:        "Random GUID: 12345678-abcd-1234-abcd-1234567890ab",
			expected:    nil,
		},
	}

	s := Scanner{}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			results, err := s.FromData(ctx, false, []byte(tc.data))
			if err != nil {
				t.Fatalf("Error scanning data: %s", err)
			}

			// Set ExtraData to nil as we don't need to compare that
			for i := range results {
				results[i].ExtraData = nil
			}

			for i := range tc.expected {
				tc.expected[i].ExtraData = nil
			}

			if diff := pretty.Compare(results, tc.expected); diff != "" {
				t.Errorf("%s: diff: (-got +want)\n%s", tc.description, diff)
			}
		})
	}
}

func TestOpenVSXDetector_IsFalsePositive(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantFalse bool
	}{
		{
			name:      "valid guid",
			input:     "12345678-abcd-1234-abcd-1234567890ab",
			wantFalse: false,
		},
		{
			name:      "invalid guid",
			input:     "not-a-guid",
			wantFalse: true,
		},
	}

	s := Scanner{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectors.Result{
				Raw: []byte(tt.input),
			}
			gotFalse, _ := s.IsFalsePositive(result)
			if gotFalse != tt.wantFalse {
				t.Errorf("IsFalsePositive() gotFalse = %v, want %v", gotFalse, tt.wantFalse)
			}
		})
	}
}