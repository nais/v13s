package sources

import (
	"context"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

type Source interface {
	ListVulnerabilitySummaries(ctx context.Context, filter vulnerabilities.Filter) ([]*vulnerabilities.WorkloadVulnerabilities, error)
}
