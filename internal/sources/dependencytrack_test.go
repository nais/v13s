package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/nais/dependencytrack/pkg/dependencytrack"
	dependencytrackMock "github.com/nais/v13s/internal/mocks/Client"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func ptr[T any](v T) *T {
	return &v
}

func TestMaintainSuppressedVulnerabilities_GetAnalysisError(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())
	mockClient := new(dependencytrackMock.MockClient)
	source := NewDependencytrackSource(mockClient, log)

	metadata := &dependencytrack.VulnMetadata{
		ProjectId:         "project-1",
		ComponentId:       "component-1",
		VulnerabilityUuid: "vuln-1",
	}

	suppressed := []*SuppressedVulnerability{
		{Metadata: metadata, CveId: "CVE-2025-0001", Suppressed: true},
	}

	mockClient.On("GetAnalysisTrailForImage", ctx, "project-1", "component-1", "vuln-1").
		Return(nil, errors.New("api failure"))

	tokens, err := source.UpdateSuppressedVulnerabilities(ctx, suppressed)
	assert.Error(t, err)
	assert.Nil(t, tokens)

	mockClient.AssertExpectations(t)
}

func TestMaintainSuppressedVulnerabilities_UpdateFindingError(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())

	mockClient := new(dependencytrackMock.MockClient)
	source := NewDependencytrackSource(mockClient, log)

	metadata := &dependencytrack.VulnMetadata{
		ProjectId:         "project-1",
		ComponentId:       "component-1",
		VulnerabilityUuid: "vuln-1",
	}

	suppressed := []*SuppressedVulnerability{
		{Metadata: metadata, CveId: "CVE-2025-0001", Suppressed: true, State: "NOT_AFFECTED"},
	}

	mockClient.On("GetAnalysisTrailForImage", ctx, "project-1", "component-1", "vuln-1").
		Return(&dependencytrack.Analysis{
			AnalysisState: "ACTIVE", // different state to trigger update
			IsSuppressed:  ptr(false),
		}, nil)

	mockClient.On("UpdateFinding", ctx, mock.Anything).
		Return(errors.New("update failure"))

	tokens, err := source.UpdateSuppressedVulnerabilities(ctx, suppressed)
	assert.Error(t, err)
	assert.Nil(t, tokens)

	mockClient.AssertExpectations(t)
}
