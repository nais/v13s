//go:build integration_test

package grpcvulnerabilities

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type afterSummaryListQuerier struct {
	sql.Querier
	afterList func(context.Context) error
}

func (q *afterSummaryListQuerier) ListVulnerabilitySummaries(ctx context.Context, params sql.ListVulnerabilitySummariesParams) ([]*sql.ListVulnerabilitySummariesRow, error) {
	rows, err := q.Querier.ListVulnerabilitySummaries(ctx, params)
	if err != nil {
		return nil, err
	}
	return rows, q.afterList(ctx)
}

func TestSummaryPackageCountsShareSnapshotWithNodes(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES
			('snapshot-summary', 'current', 'updated'), ('snapshot-summary', 'next', 'updated');
		INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag, state)
			VALUES ('snapshot-app', 'app', 'snapshot-team', 'dev', 'snapshot-summary', 'current', 'updated');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
			VALUES ('CVE-snapshot-summary', '', '', '', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version)
			VALUES ('snapshot-summary', 'current', 'pkg:npm/example@1', 'CVE-snapshot-summary', 'test', '');
		INSERT INTO vulnerability_summary (image_name, image_tag, critical, high, medium, low, unassigned, risk_score)
			VALUES ('snapshot-summary', 'current', 0, 1, 0, 0, 0, 1);
	`)
	require.NoError(t, err)
	server := NewServer(pool, logrus.NewEntry(logrus.New()))
	readSnapshot := server.readSnapshot
	server.readSnapshot = func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
		return readSnapshot(ctx, func(ctx context.Context, q sql.Querier) error {
			return read(ctx, &afterSummaryListQuerier{
				Querier: q,
				afterList: func(ctx context.Context) error {
					_, err := pool.Exec(ctx, `UPDATE workloads SET image_tag = 'next' WHERE name = 'snapshot-app'`)
					return err
				},
			})
		})
	}
	request := &vulnerabilities.ListVulnerabilitySummariesRequest{
		Filter: &vulnerabilities.Filter{Namespace: new("snapshot-team")}, PackageType: new("npm"), Limit: 10,
	}
	response, err := server.ListVulnerabilitySummaries(ctx, request)
	require.NoError(t, err)
	require.Len(t, response.GetNodes(), 1)
	require.Equal(t, "current", response.Nodes[0].GetWorkload().GetImageTag())
	require.Equal(t, int64(1), response.GetPageInfo().GetTotalCount())
	require.Len(t, response.GetPackageTypeCounts(), 1)
	require.Equal(t, "npm", response.PackageTypeCounts[0].GetValue())
	require.Equal(t, int64(1), response.PackageTypeCounts[0].GetCount())

	response, err = server.ListVulnerabilitySummaries(ctx, request)
	require.NoError(t, err)
	require.Empty(t, response.GetNodes())
	require.Zero(t, response.GetPageInfo().GetTotalCount())
	require.Empty(t, response.GetPackageTypeCounts())
}
