package helpers

import (
	"fmt"
	"math"
	"strings"
)

// MustIntToInt32 converts an int to int32, panicking if overflow would occur.
// Use only when you're certain the value is within range (e.g., CLI pagination limits).
func MustIntToInt32(n int) int32 {
	if n > math.MaxInt32 || n < math.MinInt32 {
		panic(fmt.Sprintf("integer %d overflows int32", n))
	}
	return int32(n)
}

// SplitImageRef splits an image reference into name and tag/digest.
// Handles:
//   - name:tag          (splits on last colon)
//   - name@sha256:...   (splits on @)
//
// Returns an error if neither separator is found or the tag/digest is empty.
func SplitImageRef(ref string) (name, tag string, err error) {
	if before, after, ok := strings.Cut(ref, "@"); ok {
		name = before
		tag = after
		if name == "" || tag == "" {
			return "", "", fmt.Errorf("invalid image format %q, expected <image>@<digest>", ref)
		}
		return name, tag, nil
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("invalid image format %q, expected <image>:<tag>", ref)
	}
	return ref[:i], ref[i+1:], nil
}
