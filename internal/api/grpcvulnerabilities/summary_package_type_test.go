package grpcvulnerabilities

import (
	"context"
	"errors"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	sqlmock "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSummaryPackageTypeValidation(t *testing.T) {
	for _, packageType := range []string{"", "Maven", "pkg:npm", "npm/", "npm%", " npm", "npm\n"} {
		t.Run(packageType, func(t *testing.T) {
			_, err := (&Server{}).ListVulnerabilitySummaries(context.Background(), &vulnerabilities.ListVulnerabilitySummariesRequest{
				PackageType: &packageType,
			})
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	_, err := (&Server{}).ListVulnerabilitySummaries(context.Background(), &vulnerabilities.ListVulnerabilitySummariesRequest{
		PackageType: new("npm"), Since: timestamppb.Now(),
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "package_type cannot be combined with since", status.Convert(err).Message())
}

func TestSummaryPackageTypeParameters(t *testing.T) {
	ctx := context.Background()
	for _, packageType := range []*string{nil, new("npm"), new("maven"), new("a.b+c-1")} {
		name := "unfiltered"
		if packageType != nil {
			name = *packageType
		}
		t.Run(name, func(t *testing.T) {
			q := sqlmock.NewMockQuerier(t)
			q.EXPECT().ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
				Cluster: new("dev"), Namespace: new("team"), ImageName: new("image"), ImageTag: new("v1"),
				PackageType: packageType, WorkloadTypes: []string{"app", "job"},
				RiskTiers: []int32{2}, HasKev: new(true), Limit: 10, OrderBy: "critical_asc",
			}).Return(nil, nil).Once()
			q.EXPECT().ListWorkloadPackageTypes(ctx, sql.ListWorkloadPackageTypesParams{
				Cluster: new("dev"), Namespace: new("team"), ImageName: new("image"), ImageTag: new("v1"),
				WorkloadTypes: []string{"app", "job"},
			}).Return([]*sql.ListWorkloadPackageTypesRow{{Value: "maven", Count: 3}, {Value: "npm", Count: 2}}, nil).Once()
			server := &Server{readSnapshot: func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
				return read(ctx, q)
			}}
			response, err := server.ListVulnerabilitySummaries(ctx, &vulnerabilities.ListVulnerabilitySummariesRequest{
				PackageType: packageType, Limit: 10,
				Filter: &vulnerabilities.Filter{
					Cluster: new("dev"), Namespace: new("team"), ImageName: new("image"), ImageTag: new("v1"),
					Priorities: []vulnerabilities.Priority{vulnerabilities.Priority_PRIORITY_HIGH}, HasKev: new(true),
				},
			})
			require.NoError(t, err)
			assert.Equal(t, []*vulnerabilities.PackageTypeCount{{Value: "maven", Count: 3}, {Value: "npm", Count: 2}}, response.GetPackageTypeCounts())
		})
	}
}

func TestSummaryPackageTypeEmptyPage(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		limit  int32
		offset int32
	}{
		{name: "zero limit"},
		{name: "exhausted page", limit: 1, offset: 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := sqlmock.NewMockQuerier(t)
			params := sql.ListVulnerabilitySummariesParams{
				PackageType: new("npm"), WorkloadTypes: []string{"app", "job"},
				Limit: tc.limit, Offset: tc.offset, OrderBy: "critical_asc",
			}
			q.EXPECT().ListVulnerabilitySummaries(ctx, params).Return(nil, nil).Once()
			params.Limit, params.Offset = 1, 0
			q.EXPECT().ListVulnerabilitySummaries(ctx, params).Return([]*sql.ListVulnerabilitySummariesRow{{TotalCount: 3}}, nil).Once()
			q.EXPECT().ListWorkloadPackageTypes(ctx, sql.ListWorkloadPackageTypesParams{
				WorkloadTypes: []string{"app", "job"},
			}).Return([]*sql.ListWorkloadPackageTypesRow{{Value: "apk", Count: 4}, {Value: "npm", Count: 2}}, nil).Once()
			server := &Server{readSnapshot: func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
				return read(ctx, q)
			}}
			response, err := server.ListVulnerabilitySummaries(ctx, &vulnerabilities.ListVulnerabilitySummariesRequest{
				PackageType: new("npm"), Limit: tc.limit, Offset: tc.offset,
			})
			require.NoError(t, err)
			assert.Empty(t, response.GetNodes())
			assert.Equal(t, int64(3), response.GetPageInfo().GetTotalCount())
			assert.Equal(t, []*vulnerabilities.PackageTypeCount{{Value: "apk", Count: 4}, {Value: "npm", Count: 2}}, response.GetPackageTypeCounts())
		})
	}
}

func TestSummaryPackageTypesFailures(t *testing.T) {
	ctx := context.Background()
	databaseErr := errors.New("database unavailable")
	for _, tc := range []struct {
		name  string
		types []*sql.ListWorkloadPackageTypesRow
		err   error
	}{
		{name: "query fails", err: databaseErr},
		{name: "invalid registered type", types: []*sql.ListWorkloadPackageTypesRow{{Value: "pkg:npm/private-package", Count: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := sqlmock.NewMockQuerier(t)
			q.EXPECT().ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
				WorkloadTypes: []string{"app", "job"}, Limit: 10, OrderBy: "critical_asc",
			}).Return(nil, nil).Once()
			q.EXPECT().ListWorkloadPackageTypes(ctx, sql.ListWorkloadPackageTypesParams{
				WorkloadTypes: []string{"app", "job"},
			}).Return(tc.types, tc.err).Once()
			server := &Server{readSnapshot: func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
				return read(ctx, q)
			}}
			response, err := server.ListVulnerabilitySummaries(ctx, &vulnerabilities.ListVulnerabilitySummariesRequest{Limit: 10})
			assert.Nil(t, response)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.Equal(t, codes.Internal, status.Code(err))
				assert.NotContains(t, err.Error(), "private-package")
			}
		})
	}
}

func TestSummaryPackageCountsCanBeOmitted(t *testing.T) {
	ctx := context.Background()
	for _, offset := range []int32{0, 100} {
		t.Run(map[bool]string{true: "empty page", false: "first page"}[offset > 0], func(t *testing.T) {
			q := sqlmock.NewMockQuerier(t)
			params := sql.ListVulnerabilitySummariesParams{
				PackageType: new("npm"), WorkloadTypes: []string{"app", "job"},
				Limit: 10, Offset: offset, OrderBy: "critical_asc",
			}
			rows := []*sql.ListVulnerabilitySummariesRow{{WorkloadName: "app", TotalCount: 3}}
			if offset == 0 {
				q.EXPECT().ListVulnerabilitySummaries(ctx, params).Return(rows, nil).Once()
			} else {
				q.EXPECT().ListVulnerabilitySummaries(ctx, params).Return(nil, nil).Once()
				params.Limit, params.Offset = 1, 0
				q.EXPECT().ListVulnerabilitySummaries(ctx, params).Return(rows, nil).Once()
			}
			server := &Server{readSnapshot: func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
				return read(ctx, q)
			}}
			response, err := server.ListVulnerabilitySummaries(ctx, &vulnerabilities.ListVulnerabilitySummariesRequest{
				PackageType: new("npm"), Limit: 10, Offset: offset, IncludePackageTypeCounts: new(false),
			})
			require.NoError(t, err)
			assert.Equal(t, int64(3), response.GetPageInfo().GetTotalCount())
			assert.Empty(t, response.GetPackageTypeCounts())
			if offset == 0 {
				require.Len(t, response.GetNodes(), 1)
				assert.Equal(t, "app", response.Nodes[0].GetWorkload().GetName())
			} else {
				assert.Empty(t, response.GetNodes())
			}
		})
	}
}

func TestSummaryPackageTypeSnapshotFailure(t *testing.T) {
	ctx := context.Background()
	snapshotErr := errors.New("snapshot failed")
	for _, readBeforeFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "begin", true: "commit"}[readBeforeFailure], func(t *testing.T) {
			q := sqlmock.NewMockQuerier(t)
			if readBeforeFailure {
				q.EXPECT().ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
					WorkloadTypes: []string{"app", "job"}, Limit: 10, OrderBy: "critical_asc",
				}).Return(nil, nil).Once()
				q.EXPECT().ListWorkloadPackageTypes(ctx, sql.ListWorkloadPackageTypesParams{
					WorkloadTypes: []string{"app", "job"},
				}).Return(nil, nil).Once()
			}
			server := &Server{readSnapshot: func(ctx context.Context, read func(context.Context, sql.Querier) error) error {
				if readBeforeFailure {
					require.NoError(t, read(ctx, q))
				}
				return snapshotErr
			}}
			response, err := server.ListVulnerabilitySummaries(ctx, &vulnerabilities.ListVulnerabilitySummariesRequest{Limit: 10})
			assert.Nil(t, response)
			assert.ErrorIs(t, err, snapshotErr)
		})
	}
}
