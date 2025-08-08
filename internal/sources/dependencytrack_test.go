package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/nais/dependencytrack/pkg/dependencytrack"
	dependencytrackMock "github.com/nais/v13s/mocks/github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMaintainSuppressedVulnerabilities(t *testing.T) {
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
		{
			CveId:      "CVE-2025-0001",
			Package:    "libfoo",
			Suppressed: true,
			State:      "NOT_AFFECTED",
			Metadata:   metadata,
		},
	}

	// Expect GetAnalysisTrailForImage to return analysis with different state
	mockClient.On("GetAnalysisTrailForImage", ctx, "project-1", "component-1", "vuln-1").
		Return(&dependencytrack.Analysis{
			AnalysisState: "NOT_AFFECTED",
			IsSuppressed:  ptr(false),
		}, nil)

	// Expect UpdateFinding to be called
	mockClient.On("UpdateFinding", ctx, mock.MatchedBy(func(req dependencytrack.AnalysisRequest) bool {
		return req.ProjectId == "project-1" &&
			req.ComponentId == "component-1" &&
			req.VulnerabilityId == "vuln-1" &&
			req.State == "NOT_AFFECTED" &&
			req.Suppressed
	})).Return(nil)

	// Expect TriggerAnalysis
	mockClient.On("TriggerAnalysis", ctx, "project-1").Return(nil)

	err := source.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

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

	err := source.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.Error(t, err)

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

	err := source.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestMaintainSuppressedVulnerabilities_NoUpdateNeeded(t *testing.T) {
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
			AnalysisState: "NOT_AFFECTED",
			IsSuppressed:  ptr(true),
		}, nil)

	err := source.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.NoError(t, err)

	// UpdateFinding and TriggerAnalysis should NOT be called
	mockClient.AssertNotCalled(t, "UpdateFinding", mock.Anything, mock.Anything)
	mockClient.AssertNotCalled(t, "TriggerAnalysis", mock.Anything, mock.Anything)

	mockClient.AssertExpectations(t)
}

func TestMaintainSuppressedVulnerabilities_EmptyList(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())

	mockClient := new(dependencytrackMock.MockClient)
	source := NewDependencytrackSource(mockClient, log)

	var suppressed []*SuppressedVulnerability

	err := source.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}
