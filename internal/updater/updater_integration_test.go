package updater_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/dependencytrack/client"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUpdater(t *testing.T) {
	ctx := context.Background()

	pool := test.GetPool(ctx, t, false)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	assert.NoError(t, err)

	projectNames := []string{"project-1", "project-2", "project-3", "project-4"}
	dpTrack := NewMock(projectNames)
	u := updater.NewUpdater(db, dpTrack, 200*time.Millisecond)

	t.Run("images in initialized state should be updated and vulnerabilities fetched", func(t *testing.T) {
		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(1*time.Second))
		defer cancel()

		for _, p := range projectNames {
			err := db.CreateImage(ctx, sql.CreateImageParams{
				Name:     p,
				Tag:      "v1",
				Metadata: map[string]string{"key": "value"},
			})
			assert.NoError(t, err)

			err = db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
				Name:         fmt.Sprintf("workload-%s", p),
				WorkloadType: "app",
				Namespace:    "namespace-1",
				Cluster:      "cluster-1",
				ImageName:    p,
				ImageTag:     "v1",
			})
		}

		err = u.Run(updaterCtx)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unexpected error: %s", err)
			}
		}

		imageName := projectNames[0]
		imageTag := "v1"

		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: imageName,
			Tag:  imageTag,
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateUpdated, image.State)

		vulns, err := db.ListVulnerabilities(ctx, sql.ListVulnerabilitiesParams{
			ImageName: &imageName,
			ImageTag:  &imageTag,
			Limit:     100,
		})
		assert.NoError(t, err)
		assert.Len(t, vulns, 4)
		assert.True(t, collections.AnyMatch(vulns, func(r *sql.ListVulnerabilitiesRow) bool {
			return r.ImageName == imageName && r.ImageTag == imageTag && r.CveID == fmt.Sprintf("CVE-%s-0", imageName)
		}))

	})
}

var _ dependencytrack.Client = (*MockDtrack)(nil)

type MockDtrack struct {
	projects []*client.Project
	findings map[string][]client.Finding
}

func (m MockDtrack) GetFindings(ctx context.Context, uuid string, suppressed bool) ([]client.Finding, error) {
	for _, p := range m.projects {
		if p.Uuid == uuid {
			return m.findings[uuid], nil
		}
	}
	return nil, fmt.Errorf("project not found")
}

func (m MockDtrack) GetProjectsByTag(ctx context.Context, tag string, limit, offset int32) ([]client.Project, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetProject(ctx context.Context, name, version string) (*client.Project, error) {
	for _, p := range m.projects {
		if *p.Name == name && *p.Version == version {
			return p, nil
		}
	}
	return nil, fmt.Errorf("project not found")
}

func (m MockDtrack) GetProjects(ctx context.Context, limit, offset int32) ([]client.Project, error) {
	//TODO implement me
	panic("implement me")
}

func NewMock(projectNames []string) *MockDtrack {
	mapFindings := make(map[string][]client.Finding)

	projects := make([]*client.Project, 0)

	for _, p := range projectNames {
		id := uuid.New().String()
		critical := int32(1)
		high := int32(2)
		medium := int32(3)
		low := int32(4)
		unassigned := int32(5)
		riskScore := float64(6)
		version := "v1"

		projects = append(projects, &client.Project{
			Name:    &p,
			Version: &version,
			Uuid:    id,
			Metrics: &client.ProjectMetrics{
				Critical:           critical,
				High:               high,
				Medium:             medium,
				Low:                low,
				Unassigned:         &unassigned,
				InheritedRiskScore: &riskScore,
			},
		})

		findings := make([]client.Finding, 0)
		for j := 0; j < 4; j++ {
			findings = append(findings, client.Finding{
				Component: map[string]interface{}{
					"purl": fmt.Sprintf("pkg:component-%d", j),
				},
				Vulnerability: map[string]interface{}{
					"severity":    "CRITICAL",
					"source":      "NVD",
					"title":       "title",
					"description": "description",
					"vulnId":      fmt.Sprintf("CVE-%s-%d", p, j),
				},
				Analysis: map[string]interface{}{
					"isSuppressed": false,
				},
			})
		}
		mapFindings[id] = findings
	}

	return &MockDtrack{
		projects: projects,
		findings: mapFindings,
	}
}
