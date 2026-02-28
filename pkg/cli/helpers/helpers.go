package helpers

import (
	"fmt"
	"math"
)

// MustIntToInt32 converts an int to int32, panicking if overflow would occur.
// Use only when you're certain the value is within range (e.g., CLI pagination limits).
func MustIntToInt32(n int) int32 {
	if n > math.MaxInt32 || n < math.MinInt32 {
		panic(fmt.Sprintf("integer %d overflows int32", n))
	}
	return int32(n)
}
