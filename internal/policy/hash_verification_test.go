package policy

import (
	"testing"

	vulnerabilities "github.com/nais/v13s/pkg/api/vulnerabilities"
)

func TestComputeHashVerificationStatus(t *testing.T) {
	tests := []struct {
		name      string
		component map[string]string
		registry  map[string]string
		want      vulnerabilities.HashVerificationStatus
	}{
		{
			name:      "no registry hash at all",
			component: map[string]string{"sha256": "abc"},
			registry:  nil,
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_NO_REGISTRY_HASH,
		},
		{
			name:      "no component hash at all",
			component: nil,
			registry:  map[string]string{"sha256": "abc"},
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_NO_COMPONENT_HASH,
		},
		{
			name:      "no shared algorithm",
			component: map[string]string{"sha1": "abc"},
			registry:  map[string]string{"sha256": "def"},
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_UNKNOWN,
		},
		{
			name:      "matching sha256",
			component: map[string]string{"sha256": "abc123"},
			registry:  map[string]string{"sha256": "abc123"},
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_PASSED,
		},
		{
			name:      "matching, case-insensitive",
			component: map[string]string{"sha256": "ABC123"},
			registry:  map[string]string{"sha256": "abc123"},
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_PASSED,
		},
		{
			name:      "differing sha256",
			component: map[string]string{"sha256": "abc123"},
			registry:  map[string]string{"sha256": "def456"},
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_FAILED,
		},
		{
			name:      "one shared algorithm matches, one differs, still failed",
			component: map[string]string{"sha1": "same", "sha256": "abc123"},
			registry:  map[string]string{"sha1": "same", "sha256": "def456"},
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_FAILED,
		},
		{
			name:      "extra unmatched algorithms on either side are ignored",
			component: map[string]string{"md5": "xxx", "sha256": "abc123"},
			registry:  map[string]string{"sha256": "abc123", "sha512": "yyy"},
			want:      vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_PASSED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeHashVerificationStatus(tt.component, tt.registry)
			if got != tt.want {
				t.Errorf("ComputeHashVerificationStatus(%v, %v) = %v, want %v", tt.component, tt.registry, got, tt.want)
			}
		})
	}
}
