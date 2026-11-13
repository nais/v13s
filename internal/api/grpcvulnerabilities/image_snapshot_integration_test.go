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

type afterImageListQuerier struct {
	sql.Querier
	afterList func(context.Context) error
}

func (q *afterImageListQuerier) ListVulnerabilitiesForImage(ctx context.Context, params sql.ListVulnerabilitiesForImageParams) ([]*sql.ListVulnerabilitiesForImageRow, error) {
	rows, err := q.Querier.ListVulnerabilitiesForImage(ctx, params)
	if err != nil {
		return nil, err
	}
	return rows, q.afterList(ctx)
}

func TestImagePackageCountsShareSnapshotWithNodes(t *testing.T) {
	ctx := t.Context()
	pool := test.GetPool(ctx, t, true)
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES ('snapshot-image', 'current', 'updated');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
			VALUES ('CVE-snapshot', '', '', '', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version)
			VALUES ('snapshot-image', 'current', 'pkg:npm/example@1', 'CVE-snapshot', 'test', '');
	`)
	require.NoError(t, err)
	server := NewServer(pool, logrus.NewEntry(logrus.New()))
	readSnapshot := server.readSnapshot
	server.readSnapshot = func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
		return readSnapshot(ctx, func(ctx context.Context, q sql.Querier) error {
			return read(ctx, &afterImageListQuerier{
				Querier: q,
				afterList: func(ctx context.Context) error {
					_, err := pool.Exec(ctx, `
						INSERT INTO suppressed_vulnerabilities (image_name, package, cve_id, suppressed)
							VALUES ('snapshot-image', 'pkg:npm/example@1', 'CVE-snapshot', TRUE)
							ON CONFLICT DO NOTHING;
					`)
					return err
				},
			})
		})
	}
	request := &vulnerabilities.ListVulnerabilitiesForImageRequest{
		ImageName: "snapshot-image", ImageTag: "current", Limit: 10,
	}
	response, err := server.ListVulnerabilitiesForImage(ctx, request)
	require.NoError(t, err)
	require.Len(t, response.GetNodes(), 1)
	require.Len(t, response.GetPackageTypeCounts(), 1)
	require.Equal(t, "npm", response.PackageTypeCounts[0].GetValue())
	require.Equal(t, int64(1), response.PackageTypeCounts[0].GetCount())

	response, err = server.ListVulnerabilitiesForImage(ctx, request)
	require.NoError(t, err)
	require.Empty(t, response.GetNodes())
	require.Empty(t, response.GetPackageTypeCounts())
}
