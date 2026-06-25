package helpers

import "testing"

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		wantName string
		wantTag  string
		wantErr  bool
	}{
		{
			name:     "image with tag",
			ref:      "repo/app:v1",
			wantName: "repo/app",
			wantTag:  "v1",
		},
		{
			name:     "image with digest only",
			ref:      "repo/app@sha256:abc",
			wantName: "repo/app",
			wantTag:  "sha256:abc",
		},
		{
			name:     "image with tag and digest",
			ref:      "repo/app:v1@sha256:abc",
			wantName: "repo/app",
			wantTag:  "v1@sha256:abc",
		},
		{
			name:     "registry with port tag and digest",
			ref:      "registry.example:5000/repo/app:v1@sha256:abc",
			wantName: "registry.example:5000/repo/app",
			wantTag:  "v1@sha256:abc",
		},
		{
			name:    "missing separator",
			ref:     "repo/app",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotTag, err := SplitImageRef(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotName != tt.wantName {
				t.Fatalf("name mismatch: got %q want %q", gotName, tt.wantName)
			}
			if gotTag != tt.wantTag {
				t.Fatalf("tag mismatch: got %q want %q", gotTag, tt.wantTag)
			}
		})
	}
}
