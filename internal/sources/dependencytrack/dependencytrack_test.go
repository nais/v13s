package dependencytrack

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	dependencytrackMock "github.com/nais/v13s/internal/mocks/Client"
	"github.com/nais/v13s/internal/sources/source"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMaintainSuppressedVulnerabilities(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())

	mockClient := new(dependencytrackMock.MockClient)

	dpSource := NewDependencytrackSource(mockClient, log)

	metadata := &dependencytrack.VulnMetadata{
		ProjectId:         "project-1",
		ComponentId:       "component-1",
		VulnerabilityUuid: "vuln-1",
	}

	suppressed := []*source.SuppressedVulnerability{
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

	err := dpSource.MaintainSuppressedVulnerabilities(ctx, suppressed)
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
	dpSource := NewDependencytrackSource(mockClient, log)

	metadata := &dependencytrack.VulnMetadata{
		ProjectId:         "project-1",
		ComponentId:       "component-1",
		VulnerabilityUuid: "vuln-1",
	}

	suppressed := []*source.SuppressedVulnerability{
		{Metadata: metadata, CveId: "CVE-2025-0001", Suppressed: true},
	}

	mockClient.On("GetAnalysisTrailForImage", ctx, "project-1", "component-1", "vuln-1").
		Return(nil, errors.New("api failure"))

	err := dpSource.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestMaintainSuppressedVulnerabilities_UpdateFindingError(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())

	mockClient := new(dependencytrackMock.MockClient)
	dpSource := NewDependencytrackSource(mockClient, log)

	metadata := &dependencytrack.VulnMetadata{
		ProjectId:         "project-1",
		ComponentId:       "component-1",
		VulnerabilityUuid: "vuln-1",
	}

	suppressed := []*source.SuppressedVulnerability{
		{Metadata: metadata, CveId: "CVE-2025-0001", Suppressed: true, State: "NOT_AFFECTED"},
	}

	mockClient.On("GetAnalysisTrailForImage", ctx, "project-1", "component-1", "vuln-1").
		Return(&dependencytrack.Analysis{
			AnalysisState: "ACTIVE", // different state to trigger update
			IsSuppressed:  ptr(false),
		}, nil)

	mockClient.On("UpdateFinding", ctx, mock.Anything).
		Return(errors.New("update failure"))

	err := dpSource.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.Error(t, err)

	mockClient.AssertExpectations(t)
}

func TestMaintainSuppressedVulnerabilities_NoUpdateNeeded(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())

	mockClient := new(dependencytrackMock.MockClient)
	dpSource := NewDependencytrackSource(mockClient, log)

	metadata := &dependencytrack.VulnMetadata{
		ProjectId:         "project-1",
		ComponentId:       "component-1",
		VulnerabilityUuid: "vuln-1",
	}

	suppressed := []*source.SuppressedVulnerability{
		{Metadata: metadata, CveId: "CVE-2025-0001", Suppressed: true, State: "NOT_AFFECTED"},
	}

	mockClient.On("GetAnalysisTrailForImage", ctx, "project-1", "component-1", "vuln-1").
		Return(&dependencytrack.Analysis{
			AnalysisState: "NOT_AFFECTED",
			IsSuppressed:  ptr(true),
		}, nil)

	err := dpSource.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.NoError(t, err)

	mockClient.AssertNotCalled(t, "UpdateFinding", mock.Anything, mock.Anything)
	mockClient.AssertNotCalled(t, "TriggerAnalysis", mock.Anything, mock.Anything)

	mockClient.AssertExpectations(t)
}

func TestMaintainSuppressedVulnerabilities_EmptyList(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())

	mockClient := new(dependencytrackMock.MockClient)
	dpSource := NewDependencytrackSource(mockClient, log)

	var suppressed []*source.SuppressedVulnerability

	err := dpSource.MaintainSuppressedVulnerabilities(ctx, suppressed)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}
func TestDependencytrackSource(t *testing.T) {
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())
	mockClient := new(dependencytrackMock.MockClient)
	dpSource := NewDependencytrackSource(mockClient, log)

	t.Run("IsTaskInProgress", func(t *testing.T) {
		validUUID := uuid.New().String()
		cases := []struct {
			name       string
			token      string
			mockRet    bool
			mockErr    error
			wantErr    bool
			wantExists bool
		}{
			{"InvalidUUID", "not-uuid", false, nil, true, false},
			{"ValidUUID", validUUID, true, nil, false, true},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				mockClient.ExpectedCalls = nil
				if tt.name == "ValidUUID" {
					mockClient.On("IsTaskInProgress", ctx, tt.token).Return(tt.mockRet, tt.mockErr)
				}

				got, err := dpSource.IsTaskInProgress(ctx, tt.token)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.wantExists, got)
				}

				mockClient.AssertExpectations(t)
			})
		}
	})

	t.Run("UploadAttestation", func(t *testing.T) {
		validUUID := uuid.New().String()
		cases := []struct {
			name     string
			mockRet  interface{}
			mockErr  error
			wantErr  bool
			idCheck  string
			tokenChk string
		}{
			{"Success", &dependencytrack.UploadSbomResponse{Uuid: validUUID, Token: "tok"}, nil, false, validUUID, "tok"},
			{"ClientError", nil, dependencytrack.ClientError{}, true, "", ""},
			{"ServerError", nil, dependencytrack.ServerError{}, true, "", ""},
			{"UnknownError", nil, errors.New("unknown"), true, "", ""},
			{"InvalidUUID", &dependencytrack.UploadSbomResponse{Uuid: "not-uuid", Token: "tok"}, nil, true, "", ""},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				mockClient.ExpectedCalls = nil
				mockClient.On("CreateProjectWithSbom", ctx, "img", "tag", []byte("sbom")).
					Return(tt.mockRet, tt.mockErr)

				res, err := dpSource.UploadAttestation(ctx, "img", "tag", []byte("sbom"))
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.idCheck, res.AttestationId.String())
					assert.Equal(t, tt.tokenChk, res.ProcessToken)
				}

				mockClient.AssertExpectations(t)
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		cases := []struct {
			name          string
			project       *dependencytrack.Project
			getErr        error
			deleteErr     error
			wantErr       bool
			expectDeleted bool
		}{
			{"NoProject", nil, nil, nil, false, false},
			{"Success", &dependencytrack.Project{Uuid: "uuid1"}, nil, nil, false, true},
			{"GetProjectError", nil, errors.New("fail"), nil, true, false},
			{"DeleteProjectError", &dependencytrack.Project{Uuid: "uuid1"}, nil, errors.New("del fail"), true, false},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				mockClient.ExpectedCalls = nil
				mockClient.On("GetProject", ctx, "img", "tag").Return(tt.project, tt.getErr)
				if tt.project != nil && tt.deleteErr == nil && tt.expectDeleted {
					mockClient.On("DeleteProject", ctx, tt.project.Uuid).Return(nil)
				} else if tt.project != nil && tt.deleteErr != nil {
					mockClient.On("DeleteProject", ctx, tt.project.Uuid).Return(tt.deleteErr)
				}

				err := dpSource.Delete(ctx, "img", "tag")
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
				mockClient.AssertExpectations(t)
			})
		}
	})

	t.Run("ProjectExists", func(t *testing.T) {
		cases := []struct {
			name       string
			project    *dependencytrack.Project
			getErr     error
			wantExists bool
			wantErr    bool
		}{
			{"NoProject", nil, nil, false, false},
			{"ProjectFound", &dependencytrack.Project{Uuid: "uuid1"}, nil, true, false},
			{"GetProjectError", nil, errors.New("fail"), false, true},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				mockClient.ExpectedCalls = nil
				mockClient.On("GetProject", ctx, "img", "tag").Return(tt.project, tt.getErr)

				got, err := dpSource.ProjectExists(ctx, "img", "tag")
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.wantExists, got)
				}

				mockClient.AssertExpectations(t)
			})
		}
	})

	t.Run("GetVulnerabilitySummary", func(t *testing.T) {
		cases := []struct {
			name        string
			image       string
			tag         string
			project     *dependencytrack.Project
			getErr      error
			wantErr     bool
			wantMetrics bool
			hack        bool
		}{
			{"NoProject", "img", "tag", nil, nil, true, false, false},
			{"NoMetrics", "img", "tag", &dependencytrack.Project{Uuid: "uuid1"}, nil, true, false, false},
			{"Success", "img", "tag", &dependencytrack.Project{Uuid: "uuid1", Metrics: &dependencytrack.ProjectMetric{Critical: 1, High: 2, Medium: 3, Low: 4, Unassigned: 5, InheritedRiskScore: 42}}, nil, false, true, false},
			{"GetProjectError", "img", "tag", nil, errors.New("fail"), true, false, false},
			{"HackCase", "nais-deploy-chicken", "tag", &dependencytrack.Project{Uuid: "uuid1", Metrics: &dependencytrack.ProjectMetric{Critical: 1}}, nil, false, true, true},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				mockClient.ExpectedCalls = nil

				lookupImage := tt.image
				lookupTag := tt.tag
				if tt.hack && strings.Contains(tt.image, "nais-deploy-chicken") {
					lookupImage = "europe-north1-docker.pkg.dev/nais-io/nais/images/testapp"
					lookupTag = "latest"
				}

				mockClient.On("GetProject", ctx, lookupImage, lookupTag).Return(tt.project, tt.getErr)

				res, err := dpSource.GetVulnerabilitySummary(ctx, tt.image, tt.tag)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					if tt.wantMetrics {
						assert.NotNil(t, res)
						assert.Equal(t, int32(tt.project.Metrics.InheritedRiskScore), res.RiskScore)
					}
				}

				mockClient.AssertExpectations(t)
			})
		}
	})

	t.Run("GetVulnerabilities", func(t *testing.T) {
		cases := []struct {
			name              string
			project           *dependencytrack.Project
			getProjectErr     error
			findings          []*dependencytrack.Vulnerability
			getFindingsErr    error
			includeSuppressed bool
			wantErr           bool
			wantCount         int
		}{
			{"NoProject", nil, nil, nil, nil, false, true, 0},
			{"GetProjectError", nil, errors.New("fail"), nil, nil, false, true, 0},
			{"GetFindingsError", &dependencytrack.Project{Uuid: "uuid1"}, nil, nil, errors.New("fail"), false, true, 0},
			{"WithMetadata", &dependencytrack.Project{Uuid: "uuid1"}, nil,
				[]*dependencytrack.Vulnerability{
					{
						Cve: &dependencytrack.Cve{
							Id:       "CVE-2025-0001",
							Title:    "title",
							Severity: dependencytrack.SeverityHigh,
							Link:     "link",
						},
						Package:       "libfoo",
						LatestVersion: "1.2.3",
						Metadata: &dependencytrack.VulnMetadata{
							ProjectId:         "proj",
							ComponentId:       "comp",
							VulnerabilityUuid: "vuln1",
						},
					},
				}, nil, false, false, 1,
			},
			{"MissingMetadata", &dependencytrack.Project{Uuid: "uuid1"}, nil,
				[]*dependencytrack.Vulnerability{
					{
						Cve: &dependencytrack.Cve{
							Id: "CVE-2025-0002",
						},
						Package: "libbar",
					},
				}, nil, false, false, 1,
			},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				mockClient.ExpectedCalls = nil
				mockClient.On("GetProject", ctx, "img", "tag").Return(tt.project, tt.getProjectErr)
				if tt.project != nil {
					mockClient.On("GetFindings", ctx, tt.project.Uuid, tt.includeSuppressed).Return(tt.findings, tt.getFindingsErr)
				}

				vulns, err := dpSource.GetVulnerabilities(ctx, "img", "tag", tt.includeSuppressed)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Len(t, vulns, tt.wantCount)
					for _, v := range vulns {
						assert.NotNil(t, v.Cve)
					}
				}

				mockClient.AssertExpectations(t)
			})
		}
	})
}
