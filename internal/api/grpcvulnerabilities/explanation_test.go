package grpcvulnerabilities

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/cveexplanation"
	"github.com/nais/v13s/internal/database/sql"
	queriermock "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetCveOptionalExplanation(t *testing.T) {
	const cveID = "CVE-2021-44228"
	for _, tc := range []struct {
		name    string
		visible bool
		err     error
	}{
		{name: "disabled"},
		{name: "present", visible: true},
		{name: "missing", visible: true, err: pgx.ErrNoRows},
		{name: "lookup failure", visible: true, err: errors.New("database unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			querier := queriermock.NewMockQuerier(t)
			priority := int32(2)
			querier.On("GetCve", mock.Anything, cveID).Return(&sql.Cve{CveID: cveID, HasKevEntry: true, Priority: &priority}, nil)
			if tc.visible {
				summary, action, model := "Forklaring", "Følg advisoryen", "gemini-test"
				querier.On("GetCveExplanation", mock.Anything, sql.GetCveExplanationParams{CveID: cveID, PromptVersion: cveexplanation.PromptVersion}).
					Return(&sql.GetCveExplanationRow{
						Summary: &summary, Action: &action, Model: &model, PromptVersion: 1,
						SourceUrls: []string{cveexplanation.CatalogURL}, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
					}, tc.err)
			}
			server := &Server{querier: querier, log: logrus.New(), explanationsVisible: tc.visible}
			result, err := server.GetCve(t.Context(), &vulnerabilities.GetCveRequest{Id: cveID})
			require.NoError(t, err)
			require.Equal(t, vulnerabilities.Priority_PRIORITY_HIGH, result.Cve.Priority)
			require.Equal(t, tc.visible && tc.err == nil, result.Cve.Explanation != nil)
			if result.Cve.Explanation != nil {
				require.Equal(t, "Forklaring", result.Cve.Explanation.Summary)
				require.Equal(t, []string{cveexplanation.CatalogURL}, result.Cve.Explanation.SourceUrls)
			}
		})
	}
}
