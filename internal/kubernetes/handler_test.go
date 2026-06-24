package kubernetes

import "testing"

func TestImageNameTag(t *testing.T) {
	tests := []struct {
		name          string
		image         string
		wantImageName string
		wantTagName   string
	}{
		{
			name:          "tag only",
			image:         "my-app:v1.2.3",
			wantImageName: "my-app",
			wantTagName:   "v1.2.3",
		},
		{
			name:          "digest only",
			image:         "my-app@sha256:abcdef123456",
			wantImageName: "my-app",
			wantTagName:   "sha256:abcdef123456",
		},
		{
			name:          "tag and digest",
			image:         "my-app:v1.2.3@sha256:abcdef123456",
			wantImageName: "my-app",
			wantTagName:   "v1.2.3@sha256:abcdef123456",
		},
		{
			name:          "nested repository with tag and digest",
			image:         "acme/widgets/frobnicator:v42@sha256:deadbeefcafebabe",
			wantImageName: "acme/widgets/frobnicator",
			wantTagName:   "v42@sha256:deadbeefcafebabe",
		},
		{
			name:          "nested repository with digest only",
			image:         "acme/widgets/frobnicator@sha256:deadbeefcafebabe",
			wantImageName: "acme/widgets/frobnicator",
			wantTagName:   "sha256:deadbeefcafebabe",
		},
		{
			name:          "registry with port and tag",
			image:         "registry.example:5000/my-app:v1.2.3",
			wantImageName: "registry.example:5000/my-app",
			wantTagName:   "v1.2.3",
		},
		{
			name:          "registry with port tag and digest",
			image:         "registry.example:5000/my-app:v1.2.3@sha256:abcdef123456",
			wantImageName: "registry.example:5000/my-app",
			wantTagName:   "v1.2.3@sha256:abcdef123456",
		},
		{
			name:          "image without tag",
			image:         "my-app",
			wantImageName: "my-app",
			wantTagName:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotImageName, gotTagName := imageNameTag(tt.image)

			if gotImageName != tt.wantImageName {
				t.Fatalf("imageName = %q, want %q", gotImageName, tt.wantImageName)
			}

			if gotTagName != tt.wantTagName {
				t.Fatalf("tagName = %q, want %q", gotTagName, tt.wantTagName)
			}
		})
	}
}
