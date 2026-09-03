package grpcvulnerabilities

import (
	"slices"
	"testing"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
)

func TestToSQLPriorityTiers(t *testing.T) {
	tests := []struct {
		name   string
		filter *vulnerabilities.Filter
		want   []int32
	}{
		{
			name:   "nil filter",
			filter: nil,
			want:   nil,
		},
		{
			name:   "no priorities",
			filter: &vulnerabilities.Filter{},
			want:   nil,
		},
		{
			name: "single priority maps to its tier",
			filter: &vulnerabilities.Filter{
				Priorities: []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_HIGH},
			},
			want: []int32{2},
		},
		{
			name: "multiple priorities map to distinct tiers",
			filter: &vulnerabilities.Filter{
				Priorities: []vulnerabilities.Priority{
					vulnerabilities.Priority_PRIORITY_ELEVATED,
					vulnerabilities.Priority_PRIORITY_HIGH,
				},
			},
			want: []int32{2, 3},
		},
		{
			name: "unspecified is skipped",
			filter: &vulnerabilities.Filter{
				Priorities: []vulnerabilities.Priority{
					vulnerabilities.Priority_PRIORITY_UNSPECIFIED,
					vulnerabilities.Priority_PRIORITY_MONITOR,
				},
			},
			want: []int32{4},
		},
		{
			name: "duplicates collapse to one tier",
			filter: &vulnerabilities.Filter{
				Priorities: []vulnerabilities.Priority{
					vulnerabilities.Priority_PRIORITY_HIGH,
					vulnerabilities.Priority_PRIORITY_HIGH,
				},
			},
			want: []int32{2},
		},
		{
			name: "only unspecified yields nil",
			filter: &vulnerabilities.Filter{
				Priorities: []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_UNSPECIFIED},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toSQLPriorityTiers(tt.filter)
			slices.Sort(got)
			assert.Equal(t, tt.want, got)
		})
	}
}

func legacyPriorityFilter(p vulnerabilities.Priority) *vulnerabilities.Filter {
	//lint:ignore SA1019 wire compatibility.
	return &vulnerabilities.Filter{Priority: &p}
}

func TestToSQLPriorityTiersIgnoresLegacyPriorityField(t *testing.T) {
	filter := legacyPriorityFilter(vulnerabilities.Priority_PRIORITY_HIGH)

	assert.Nil(t, toSQLPriorityTiers(filter), "exact-set filtering must not read the deprecated Filter.priority field")
}

func TestToSQLPriorityFilter(t *testing.T) {
	assert.Nil(t, toSQLPriorityFilter(nil))
	assert.Nil(t, toSQLPriorityFilter(&vulnerabilities.Filter{}))
	assert.Nil(t, toSQLPriorityFilter(legacyPriorityFilter(vulnerabilities.Priority_PRIORITY_UNSPECIFIED)))

	got := toSQLPriorityFilter(legacyPriorityFilter(vulnerabilities.Priority_PRIORITY_HIGH))
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(2), *got)
	}
}

func TestToSQLPriorityFilterExactSetTakesPrecedence(t *testing.T) {
	filter := legacyPriorityFilter(vulnerabilities.Priority_PRIORITY_HIGH)
	filter.Priorities = []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_ELEVATED}

	assert.Nil(t, toSQLPriorityFilter(filter),
		"the deprecated threshold must be ignored when Filter.priorities is set, so the two filters cannot intersect")
}

func TestPriorityRiskTiers(t *testing.T) {
	assert.Nil(t, priorityRiskTiers(nil))
	assert.Nil(t, priorityRiskTiers(&vulnerabilities.Filter{}))

	exact := priorityRiskTiers(&vulnerabilities.Filter{
		Priorities: []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_ELEVATED},
	})
	assert.Equal(t, []int32{3}, exact)

	threshold := priorityRiskTiers(legacyPriorityFilter(vulnerabilities.Priority_PRIORITY_ELEVATED))
	assert.ElementsMatch(t, []int32{1, 2, 3}, threshold)

	both := legacyPriorityFilter(vulnerabilities.Priority_PRIORITY_MONITOR)
	both.Priorities = []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_HIGH}
	assert.Equal(t, []int32{2}, priorityRiskTiers(both))
}
