package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (s *Server) resolveCanonicalCveIDs(ctx context.Context, ids []string) ([]string, error) {
	seen := make(map[string]struct{}, len(ids))
	resolved := make([]string, 0, len(ids))
	for _, id := range ids {
		canonical := id
		if canonicalID, err := s.querier.GetCanonicalCveIdByAlias(ctx, id); err == nil {
			canonical = canonicalID
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("resolve canonical cve id for %s: %w", id, err)
		}
		if _, ok := seen[canonical]; !ok {
			seen[canonical] = struct{}{}
			resolved = append(resolved, canonical)
		}
	}
	return resolved, nil
}
