package grpcmgmt

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/database/typeext"
	"github.com/nais/v13s/internal/dependencytrack"
	dpClient "github.com/nais/v13s/internal/dependencytrack/client"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestRegisterWorkload(t *testing.T) {
	ctx := context.Background()

	db := sql.NewMockQuerier(t)
	client := dependencytrack.NewMockClient(t)

	server := NewServer(db, client)

	request := &management.RegisterWorkloadRequest{
		Cluster:      "test-cluster",
		Namespace:    "test-namespace",
		Workload:     "test-workload",
		WorkloadType: "test-type",
		ImageName:    "test-image",
		ImageTag:     "test-tag",
		Metadata: &management.Metadata{
			Labels: map[string]string{},
		},
	}

	tt := []struct {
		name         string
		expectations func()
	}{
		{
			name: "should create image if it does not exist, add workload and vulnerability summary",
			expectations: func() {
				db.On("GetImage", mock.Anything, sql.GetImageParams{
					Name: request.ImageName,
					Tag:  request.ImageTag,
				}).Return(nil, pgx.ErrNoRows)

				db.On("CreateImage", mock.Anything, sql.CreateImageParams{
					Name:     request.ImageName,
					Tag:      request.ImageTag,
					Metadata: typeext.MapStringString{},
				}).Return(nil, nil)

				db.On("UpsertWorkload", mock.Anything, sql.UpsertWorkloadParams{
					Name:         request.Workload,
					WorkloadType: request.WorkloadType,
					Namespace:    request.Namespace,
					Cluster:      request.Cluster,
					ImageName:    request.ImageName,
					ImageTag:     request.ImageTag,
				}).Return(nil)

				unassigned := int32(10)
				inheritedRiskScore := float64(14)
				client.On("GetProject", mock.Anything, request.ImageName, request.ImageTag).Return(&dpClient.Project{
					Name:    &request.ImageName,
					Version: &request.ImageTag,
					Metrics: &dpClient.ProjectMetrics{
						Critical:           10,
						High:               11,
						Medium:             12,
						Low:                13,
						Unassigned:         &unassigned,
						InheritedRiskScore: &inheritedRiskScore,
					},
				}, nil)

				db.On("UpsertVulnerabilitySummary", mock.Anything, sql.UpsertVulnerabilitySummaryParams{
					ImageName:  request.ImageName,
					ImageTag:   request.ImageTag,
					Critical:   10,
					High:       11,
					Medium:     12,
					Low:        13,
					Unassigned: unassigned,
					RiskScore:  14,
				}).Return(nil)
			},
		},
		{
			name: "image exists, add workload and vulnerability summary",
			expectations: func() {
				db.On("GetImage", mock.Anything, sql.GetImageParams{
					Name: request.ImageName,
					Tag:  request.ImageTag,
				}).Return(&sql.Image{
					Name:     request.ImageName,
					Tag:      request.ImageTag,
					Metadata: nil,
				}, nil)

				db.On("UpsertWorkload", mock.Anything, sql.UpsertWorkloadParams{
					Name:         request.Workload,
					WorkloadType: request.WorkloadType,
					Namespace:    request.Namespace,
					Cluster:      request.Cluster,
					ImageName:    request.ImageName,
					ImageTag:     request.ImageTag,
				}).Return(nil)

				unassigned := int32(10)
				inheritedRiskScore := float64(14)
				client.On("GetProject", mock.Anything, request.ImageName, request.ImageTag).Return(&dpClient.Project{
					Name:    &request.ImageName,
					Version: &request.ImageTag,
					Metrics: &dpClient.ProjectMetrics{
						Critical:           10,
						High:               11,
						Medium:             12,
						Low:                13,
						Unassigned:         &unassigned,
						InheritedRiskScore: &inheritedRiskScore,
					},
				}, nil)

				db.On("UpsertVulnerabilitySummary", mock.Anything, sql.UpsertVulnerabilitySummaryParams{
					ImageName:  request.ImageName,
					ImageTag:   request.ImageTag,
					Critical:   10,
					High:       11,
					Medium:     12,
					Low:        13,
					Unassigned: unassigned,
					RiskScore:  14,
				}).Return(nil)
			},
		},
		{
			name: "no metrics found, should not add vulnerability summary, only workload",
			expectations: func() {
				db.On("GetImage", mock.Anything, sql.GetImageParams{
					Name: request.ImageName,
					Tag:  request.ImageTag,
				}).Return(&sql.Image{
					Name:     request.ImageName,
					Tag:      request.ImageTag,
					Metadata: nil,
				}, nil)

				db.On("UpsertWorkload", mock.Anything, sql.UpsertWorkloadParams{
					Name:         request.Workload,
					WorkloadType: request.WorkloadType,
					Namespace:    request.Namespace,
					Cluster:      request.Cluster,
					ImageName:    request.ImageName,
					ImageTag:     request.ImageTag,
				}).Return(nil)

				client.On("GetProject", mock.Anything, request.ImageName, request.ImageTag).Return(&dpClient.Project{
					Name:    &request.ImageName,
					Version: &request.ImageTag,
					Metrics: nil,
				}, nil)
			},
		},
	}

	for _, tc := range tt {
		tc.expectations()
		_, err := server.RegisterWorkload(ctx, request)
		assert.NoError(t, err)
	}
}
