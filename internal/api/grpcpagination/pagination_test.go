package grpcpagination

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

type MockRequest struct {
	Limit  int32
	Offset int32
}

func (m *MockRequest) GetLimit() int32  { return m.Limit }
func (m *MockRequest) GetOffset() int32 { return m.Offset }

func TestPagination(t *testing.T) {
	tests := []struct {
		name           string
		request        *MockRequest
		expectedLimit  int32
		expectedOffset int32
		expectedError  error
	}{
		{"Custom limit", &MockRequest{100, 10}, 100, 10, nil},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pageInfo, err := PageInfo(tt.request, tt.total)
			assert.Equal(t, tt.expectedInfo, pageInfo)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}
