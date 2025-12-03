package s3

import "testing"

func TestS3Unit(t *testing.T) {
	tests := []struct {
		name        string
		bucket      string
		role        string
		wantID      string
		wantDisplay string
	}{
		{
			name:        "Bucket with role",
			bucket:      "my-bucket",
			role:        "arn:aws:iam::123456789012:role/MyRole",
			wantID:      "arn:aws:iam::123456789012:role/MyRole|my-bucket",
			wantDisplay: "Role=arn:aws:iam::123456789012:role/MyRole Bucket=my-bucket",
		},
		{
			name:        "Bucket without role",
			bucket:      "my-bucket",
			wantID:      "my-bucket",
			wantDisplay: "my-bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			unit := S3SourceUnit{
				Bucket: tt.bucket,
				Role:   tt.role,
			}

			gotID, gotKind := unit.SourceUnitID()
			gotDisplay := unit.Display()

			if gotKind != SourceUnitKindBucket {
				t.Errorf("SourceUnitID() got kind = %v, want %v", gotKind, SourceUnitKindBucket)
			}
			if gotID != tt.wantID {
				t.Errorf("SourceUnitID() got id= %v, want %v", gotID, tt.wantID)
			}
			if gotDisplay != tt.wantDisplay {
				t.Errorf("Display() = %v, want %v", gotDisplay, tt.wantDisplay)
			}
		})
	}
}
