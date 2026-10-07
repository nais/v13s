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
)

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

func TestListWorkloadsForVulnerability_NamespacesMerge(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name               string
		filter             *vulnerabilities.Filter
		expectedNamespaces []string
	}{
		{
			name:               "single namespace via Namespace field",
			filter:             &vulnerabilities.Filter{Namespace: new("team-a")},
			expectedNamespaces: []string{"team-a"},
		},
		{
			name:               "multiple namespaces via Namespaces field",
			filter:             &vulnerabilities.Filter{Namespaces: []string{"team-a", "team-b"}},
			expectedNamespaces: []string{"team-a", "team-b"},
		},
		{
			name:               "both fields merged",
			filter:             &vulnerabilities.Filter{Namespace: new("team-a"), Namespaces: []string{"team-b"}},
			expectedNamespaces: []string{"team-b", "team-a"},
		},
		{
			name:               "neither set results in empty slice",
			filter:             &vulnerabilities.Filter{},
			expectedNamespaces: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := mockquerier.NewMockQuerier(t)
			srv := &Server{querier: q, log: logrus.NewEntry(logrus.New())}

			q.On("ListWorkloadsForVulnerabilities", mock.Anything, mock.MatchedBy(func(p sql.ListWorkloadsForVulnerabilitiesParams) bool {
				return assert.ElementsMatch(t, tt.expectedNamespaces, p.Namespaces)
			})).Return([]*sql.ListWorkloadsForVulnerabilitiesRow{}, nil)

			_, err := srv.ListWorkloadsForVulnerability(ctx, &vulnerabilities.ListWorkloadsForVulnerabilityRequest{
				Filter: tt.filter,
			})
			require.NoError(t, err)
		})
	}
}
