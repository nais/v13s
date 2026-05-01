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

func TestGetVulnerabilities_EpssAndCvssFieldsMapped(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())
	mockClient := new(dependencytrackMock.MockClient)
	source := NewDependencytrackSource(mockClient, log)

	cvss1, epss1, epssP1 := 5.1, 0.00527, 0.66622
	cvss2 := 7.5

	mockClient.On("GetProject", ctx, "my-image", "1.0.0").
		Return(&dependencytrack.Project{Uuid: "proj-1"}, nil)

	mockClient.On("GetFindings", ctx, "proj-1", false).
		Return([]*dependencytrack.Vulnerability{
			{
				Package: "pkg:maven/org.infinispan/infinispan-core@10.1.8.Final",
				Cve: &dependencytrack.Cve{
					Id:       "GHSA-gg57-587f-h5v6",
					Severity: dependencytrack.SeverityMedium,
				},
				Cvss:           &cvss1,
				EpssScore:      &epss1,
				EpssPercentile: &epssP1,
				Metadata: &dependencytrack.VulnMetadata{
					ProjectId:         "proj-1",
					ComponentId:       "comp-1",
					VulnerabilityUuid: "vuln-1",
				},
			},
			{
				Package: "pkg:maven/org.json/json@20090211",
				Cve: &dependencytrack.Cve{
					Id:       "GHSA-3vqj-43w4-2q58",
					Severity: dependencytrack.SeverityHigh,
				},
				Cvss:           &cvss2,
				EpssScore:      nil,
				EpssPercentile: nil,
				Metadata: &dependencytrack.VulnMetadata{
					ProjectId:         "proj-1",
					ComponentId:       "comp-2",
					VulnerabilityUuid: "vuln-2",
				},
			},
		}, nil)

	vulns, err := source.GetVulnerabilities(ctx, "my-image", "1.0.0", false)
	assert.NoError(t, err)
	assert.Len(t, vulns, 2)

	v0 := vulns[0]
	assert.Equal(t, "GHSA-gg57-587f-h5v6", v0.Cve.Id)
	assert.NotNil(t, v0.CvssScore)
	assert.Equal(t, 5.1, *v0.CvssScore)
	assert.NotNil(t, v0.EpssScore)
	assert.Equal(t, 0.00527, *v0.EpssScore)
	assert.NotNil(t, v0.EpssPercentile)
	assert.Equal(t, 0.66622, *v0.EpssPercentile)

	v1 := vulns[1]
	assert.Equal(t, "GHSA-3vqj-43w4-2q58", v1.Cve.Id)
	assert.NotNil(t, v1.CvssScore)
	assert.Equal(t, 7.5, *v1.CvssScore)
	assert.Nil(t, v1.EpssScore)
	assert.Nil(t, v1.EpssPercentile)

	mockClient.AssertExpectations(t)
}

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

	mockClient.On("GetAnalysisTrailForImage", ctx, "project-1", "component-1", "vuln-1").
		Return(&dependencytrack.Analysis{
			AnalysisState: "NOT_AFFECTED",
			IsSuppressed:  new(false),
		}, nil)

	mockClient.On("UpdateFinding", ctx, mock.MatchedBy(func(req dependencytrack.AnalysisRequest) bool {
		return req.ProjectId == "project-1" &&
			req.ComponentId == "component-1" &&
			req.VulnerabilityId == "vuln-1" &&
			req.State == "NOT_AFFECTED" &&
			req.Suppressed
	})).Return(nil)

	mockClient.On("TriggerAnalysis", ctx, "project-1").Return(nil)

	err := source.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
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
			AnalysisState: "ACTIVE",
			IsSuppressed:  new(false),
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
			IsSuppressed:  new(true),
		}, nil)

	err := source.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.NoError(t, err)

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
