package grpcpagination

import (
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

type Paginatable interface {
	GetLimit() int32
	GetOffset() int32
}

func Pagination(r Paginatable) (limit int32, offset int32, err error) {
	limit = r.GetLimit()
	return limit, r.GetOffset(), nil
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
