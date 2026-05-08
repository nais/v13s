package grpcvulnerabilities

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSuppressVulnerabilities_CrossNamespaceRejected(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	suppress := true
	_, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		CveId:    "CVE-2025-9999",
		Suppress: &suppress,
		Workloads: []*vulnerabilities.SuppressVulnerabilitiesWorkload{
			{Cluster: "c", Namespace: "ns-a", Name: "app1", WorkloadType: "Deployment"},
			{Cluster: "c", Namespace: "ns-b", Name: "app2", WorkloadType: "Deployment"},
		},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "same cluster and namespace")
}

func TestSuppressVulnerabilities_CrossClusterRejected(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	suppress := true
	_, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		CveId:    "CVE-2025-9999",
		Suppress: &suppress,
		Workloads: []*vulnerabilities.SuppressVulnerabilitiesWorkload{
			{Cluster: "c1", Namespace: "ns", Name: "app1", WorkloadType: "Deployment"},
			{Cluster: "c2", Namespace: "ns", Name: "app2", WorkloadType: "Deployment"},
		},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "same cluster and namespace")
}

func TestSuppressVulnerabilities_MissingCveId(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	suppress := true
	_, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		Suppress: &suppress,
		Workloads: []*vulnerabilities.SuppressVulnerabilitiesWorkload{
			{Cluster: "c", Namespace: "ns", Name: "app", WorkloadType: "Deployment"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cve_id is required")
}

func TestSuppressVulnerabilities_MissingWorkloads(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	suppress := true
	_, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		CveId:    "CVE-2025-9999",
		Suppress: &suppress,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one workload")
}

func TestSuppressVulnerabilities_EmptyWorkloadFields(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	suppress := true
	_, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		CveId:    "CVE-2025-9999",
		Suppress: &suppress,
		Workloads: []*vulnerabilities.SuppressVulnerabilitiesWorkload{
			{Cluster: "c", Namespace: "ns", Name: "", WorkloadType: "Deployment"},
		},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "workload[0]")
}

func TestSuppressVulnerabilities_AliasLookupError(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	q.EXPECT().GetCanonicalCveIdByAlias(ctx, "CVE-2025-9999").Return("", fmt.Errorf("db error"))

	suppress := true
	_, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		CveId:    "CVE-2025-9999",
		Suppress: &suppress,
		Workloads: []*vulnerabilities.SuppressVulnerabilitiesWorkload{
			{Cluster: "c", Namespace: "ns", Name: "app", WorkloadType: "Deployment"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve canonical cve id")
}

func TestSuppressVulnerabilities_Success(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	q.EXPECT().GetCanonicalCveIdByAlias(ctx, "CVE-2025-9999").Return("", pgx.ErrNoRows)
	q.EXPECT().GetAliasesByCanonicalCveId(ctx, "CVE-2025-9999").Return([]string{"GHSA-xxxx-yyyy-zzzz"}, nil)
	q.EXPECT().GetImagesForCveAndWorkloads(ctx, sql.GetImagesForCveAndWorkloadsParams{
		CveID:         "CVE-2025-9999",
		Clusters:      []string{"c"},
		Namespaces:    []string{"ns"},
		Names:         []string{"app"},
		WorkloadTypes: []string{"Deployment"},
	}).Return([]*sql.GetImagesForCveAndWorkloadsRow{
		{ImageName: "img", ImageTag: "v1", Package: "pkg", WorkloadCluster: "c", WorkloadNamespace: "ns", WorkloadName: "app", WorkloadType: "Deployment"},
	}, nil)

	suppress := true
	suppressedBy := "test-user"
	reason := "not affected"

	for _, cveID := range []string{"CVE-2025-9999", "GHSA-xxxx-yyyy-zzzz"} {
		q.EXPECT().SuppressVulnerability(ctx, sql.SuppressVulnerabilityParams{
			ImageName:    "img",
			Package:      "pkg",
			CveID:        cveID,
			SuppressedBy: suppressedBy,
			Suppressed:   suppress,
			Reason:       sql.VulnerabilitySuppressReasonFalsePositive,
			ReasonText:   reason,
		}).Return(nil)
	}

	q.EXPECT().RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: "img",
		ImageTag:  "v1",
	}).Return(nil)

	q.EXPECT().UpdateImageState(ctx, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.State == sql.ImageStateResync && p.Name == "img" && p.Tag == "v1" && p.ReadyForResyncAt.Valid
	})).RunAndReturn(func(_ context.Context, p sql.UpdateImageStateParams) (int64, error) {
		return 1, nil
	})

	resp, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		CveId:        "CVE-2025-9999",
		Suppress:     &suppress,
		SuppressedBy: &suppressedBy,
		Reason:       &reason,
		State:        vulnerabilities.SuppressState_FALSE_POSITIVE,
		Workloads: []*vulnerabilities.SuppressVulnerabilitiesWorkload{
			{Cluster: "c", Namespace: "ns", Name: "app", WorkloadType: "Deployment"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "CVE-2025-9999", resp.GetCveId())
	assert.True(t, resp.GetSuppressed())
	assert.Equal(t, int32(1), resp.GetWorkloadCount())
	assert.Equal(t, int32(1), resp.GetImageCount())
	assert.Empty(t, resp.GetErrors())
}

func TestSuppressVulnerabilities_PartialFailure(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	suppress := true
	suppressedBy := "test-user"
	reason := "not affected"
	dbErr := fmt.Errorf("db error")

	q.EXPECT().GetCanonicalCveIdByAlias(ctx, "CVE-2025-9999").Return("", pgx.ErrNoRows)
	q.EXPECT().GetAliasesByCanonicalCveId(ctx, "CVE-2025-9999").Return(nil, nil)
	q.EXPECT().GetImagesForCveAndWorkloads(ctx, sql.GetImagesForCveAndWorkloadsParams{
		CveID:         "CVE-2025-9999",
		Clusters:      []string{"c"},
		Namespaces:    []string{"ns"},
		Names:         []string{"app"},
		WorkloadTypes: []string{"Deployment"},
	}).Return([]*sql.GetImagesForCveAndWorkloadsRow{
		{ImageName: "img", ImageTag: "v1", Package: "pkg", WorkloadCluster: "c", WorkloadNamespace: "ns", WorkloadName: "app", WorkloadType: "Deployment"},
	}, nil)
	q.EXPECT().SuppressVulnerability(ctx, sql.SuppressVulnerabilityParams{
		ImageName:    "img",
		Package:      "pkg",
		CveID:        "CVE-2025-9999",
		SuppressedBy: suppressedBy,
		Suppressed:   suppress,
		Reason:       sql.VulnerabilitySuppressReasonFalsePositive,
		ReasonText:   reason,
	}).Return(dbErr)
	q.EXPECT().RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: "img",
		ImageTag:  "v1",
	}).Return(nil)
	q.EXPECT().UpdateImageState(ctx, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.State == sql.ImageStateResync && p.Name == "img" && p.Tag == "v1"
	})).RunAndReturn(func(_ context.Context, p sql.UpdateImageStateParams) (int64, error) {
		return 1, nil
	})

	resp, err := srv.SuppressVulnerabilities(ctx, &vulnerabilities.SuppressVulnerabilitiesRequest{
		CveId:        "CVE-2025-9999",
		Suppress:     &suppress,
		SuppressedBy: &suppressedBy,
		Reason:       &reason,
		State:        vulnerabilities.SuppressState_FALSE_POSITIVE,
		Workloads: []*vulnerabilities.SuppressVulnerabilitiesWorkload{
			{Cluster: "c", Namespace: "ns", Name: "app", WorkloadType: "Deployment"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.GetWorkloadCount())
	assert.Equal(t, int32(1), resp.GetImageCount())
	assert.Len(t, resp.GetErrors(), 1)
	assert.Contains(t, resp.GetErrors()[0], "img/pkg/CVE-2025-9999")
}

func TestSuppressVulnerability_AliasLookupError(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)

	vulnID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	id := pgtype.UUID{Bytes: vulnID, Valid: true}
	row := &sql.GetVulnerabilityByIdRow{
		ID:        id,
		ImageName: "img",
		ImageTag:  "v1",
		Package:   "pkg",
		CveID:     "CVE-2025-1234",
	}

	q.EXPECT().GetVulnerabilityById(ctx, id).Return(row, nil)
	q.EXPECT().GetCanonicalCveIdByAlias(ctx, "CVE-2025-1234").Return("", pgx.ErrNoRows)
	q.EXPECT().GetAliasesByCanonicalCveId(ctx, "CVE-2025-1234").Return(nil, fmt.Errorf("db connection lost"))

	suppress := true
	suppressedBy := "test-user"
	srv := &Server{
		querier: q,
		log:     logrus.NewEntry(logrus.New()),
	}
	_, err := srv.SuppressVulnerability(ctx, &vulnerabilities.SuppressVulnerabilityRequest{
		Id:           vulnID.String(),
		Suppress:     &suppress,
		SuppressedBy: &suppressedBy,
		State:        vulnerabilities.SuppressState_NOT_AFFECTED,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "get aliases for cve")
}

func TestListWorkloadsForVulnerability_ResolvesAlias(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	q.EXPECT().GetCanonicalCveIdByAlias(ctx, "GHSA-xxxx-yyyy-zzzz").Return("CVE-2025-1234", nil)
	q.EXPECT().ListWorkloadsForVulnerabilities(ctx, mock.MatchedBy(func(p sql.ListWorkloadsForVulnerabilitiesParams) bool {
		return len(p.CveIds) == 1 && p.CveIds[0] == "CVE-2025-1234"
	})).Return([]*sql.ListWorkloadsForVulnerabilitiesRow{}, nil)

	resp, err := srv.ListWorkloadsForVulnerability(ctx, &vulnerabilities.ListWorkloadsForVulnerabilityRequest{
		CveIds: []string{"GHSA-xxxx-yyyy-zzzz"},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.GetNodes())
}

func TestListWorkloadsForVulnerability_AliasLookupError(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

	q.EXPECT().GetCanonicalCveIdByAlias(ctx, "GHSA-xxxx-yyyy-zzzz").Return("", fmt.Errorf("db error"))

	_, err := srv.ListWorkloadsForVulnerability(ctx, &vulnerabilities.ListWorkloadsForVulnerabilityRequest{
		CveIds: []string{"GHSA-xxxx-yyyy-zzzz"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve canonical cve id")
}
