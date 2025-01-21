package grpcpagination

import (
	"errors"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

type MockRequest struct {
	Limit  int64
	Offset int64
}

func (m *MockRequest) GetLimit() int64  { return m.Limit }
func (m *MockRequest) GetOffset() int64 { return m.Offset }

func TestPagination(t *testing.T) {
	tests := []struct {
		name           string
		request        *MockRequest
		expectedLimit  int32
		expectedOffset int32
		expectedError  error
	}{
		{"Default limit", &MockRequest{0, 0}, 50, 0, nil},
		{"Custom limit", &MockRequest{100, 10}, 100, 10, nil},
		{"Exceed max int32", &MockRequest{math.MaxInt64, math.MaxInt64}, 0, 0, errors.New("limit or offset exceeds maximum int32 value")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, offset, err := Pagination(tt.request)
			assert.Equal(t, tt.expectedLimit, limit)
			assert.Equal(t, tt.expectedOffset, offset)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}

func TestPageInfo(t *testing.T) {
	tests := []struct {
		name          string
		request       *MockRequest
		total         int
		expectedInfo  *vulnerabilities.PageInfo
		expectedError error
	}{
		{
			"Valid input with next page",
			&MockRequest{50, 100},
			300,
			&vulnerabilities.PageInfo{
				TotalCount:      300,
				HasNextPage:     true,
				HasPreviousPage: true,
			},
			nil,
		},
		{
			"Input exceeds max int32",
			&MockRequest{math.MaxInt64, math.MaxInt64},
			300,
			nil,
			errors.New("limit or offset exceeds maximum int32 value"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pageInfo, err := PageInfo(tt.request, tt.total)
			assert.Equal(t, tt.expectedInfo, pageInfo)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}
