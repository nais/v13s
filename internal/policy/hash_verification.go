package policy

import (
	"strings"

	vulnerabilities "github.com/nais/v13s/pkg/api/vulnerabilities"
)

var hashAlgorithms = []string{"md5", "sha1", "sha256", "sha512"}

func normalizeHashes(hashes map[string]string) map[string]string {
	out := make(map[string]string, len(hashes))
	for _, algo := range hashAlgorithms {
		v, ok := hashes[algo]
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v != "" {
			out[algo] = strings.ToLower(v)
		}
	}
	return out
}

// ComputeHashVerificationStatus compares a component's declared hashes
// (keyed by algorithm: md5, sha1, sha256, sha512) against a package
// registry's published hashes for the same algorithms.
func ComputeHashVerificationStatus(componentHashes, registryHashes map[string]string) vulnerabilities.HashVerificationStatus {
	registry := normalizeHashes(registryHashes)
	if len(registry) == 0 {
		return vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_NO_REGISTRY_HASH
	}

	component := normalizeHashes(componentHashes)
	if len(component) == 0 {
		return vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_NO_COMPONENT_HASH
	}

	common := false
	anyFailed := false
	for _, algo := range hashAlgorithms {
		registryHash, inRegistry := registry[algo]
		componentHash, inComponent := component[algo]
		if !inRegistry || !inComponent {
			continue
		}
		common = true
		if registryHash != componentHash {
			anyFailed = true
		}
	}

	if !common {
		return vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_UNKNOWN
	}
	if anyFailed {
		return vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_FAILED
	}
	return vulnerabilities.HashVerificationStatus_HASH_VERIFICATION_STATUS_PASSED
}
