package grpcvulnerabilities

import (
	"slices"
	"testing"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
)

func TestPriorityTiersFromPriorities(t *testing.T) {
	tests := []struct {
		name       string
		priorities []vulnerabilities.Priority
		want       []int32
	}{
		{
			name:       "none",
			priorities: nil,
			want:       nil,
		},
		{
			name:       "single priority maps to its tier",
			priorities: []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_HIGH},
			want:       []int32{2},
		},
		{
			name: "multiple priorities map to distinct tiers",
			priorities: []vulnerabilities.Priority{
				vulnerabilities.Priority_PRIORITY_ELEVATED,
				vulnerabilities.Priority_PRIORITY_HIGH,
			},
			want: []int32{2, 3},
		},
		{
			name: "unspecified is skipped",
			priorities: []vulnerabilities.Priority{
				vulnerabilities.Priority_PRIORITY_UNSPECIFIED,
				vulnerabilities.Priority_PRIORITY_MONITOR,
			},
			want: []int32{4},
		},
		{
			name: "duplicates collapse to one tier",
			priorities: []vulnerabilities.Priority{
				vulnerabilities.Priority_PRIORITY_HIGH,
				vulnerabilities.Priority_PRIORITY_HIGH,
			},
			want: []int32{2},
		},
		{
			name:       "only unspecified yields nil",
			priorities: []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_UNSPECIFIED},
			want:       nil,
		},
		{
			name:       "unrecognised priority yields a non-nil empty slice (matches nothing)",
			priorities: []vulnerabilities.Priority{vulnerabilities.Priority(1)},
			want:       []int32{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := priorityTiersFromPriorities(tt.priorities)
			slices.Sort(got)
			assert.Equal(t, tt.want, got)
			if tt.want != nil {
				assert.NotNil(t, got)
			}
		})
	}
}
