package grpcpagination

import (
	"errors"
	"math"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

type Paginatable interface {
	GetLimit() int64
	GetOffset() int64
}

func Pagination(r Paginatable) (limit int32, offset int32, err error) {
	l, o := r.GetLimit(), r.GetOffset()
	if l > math.MaxInt32 || o > math.MaxInt32 {
		return 0, 0, errors.New("limit or offset exceeds maximum int32 value")
	}

	limit, offset = int32(l), int32(o)
	if limit == 0 {
		limit = 50
	}

	return limit, offset, nil
}

func PageInfo(r Paginatable, total int) (*vulnerabilities.PageInfo, error) {
	limit, offset, err := Pagination(r)
	if err != nil {
		return nil, err
	}
	return &vulnerabilities.PageInfo{
		TotalCount:      int64(total),
		HasNextPage:     int(offset)+int(limit) < total,
		HasPreviousPage: offset > 0,
	}, nil
}
