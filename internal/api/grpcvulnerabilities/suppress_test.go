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
