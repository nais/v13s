package updater_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/sources/dependencytrack"
	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// TODO: add tests for VulnerabilitySummary upserted too
func TestUpdater(t *testing.T) {
	ctx := context.Background()

	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	assert.NoError(t, err)

	projectNames := []string{"project-1", "project-2", "project-3", "project-4"}
	dpTrack := NewMock(projectNames)
	updateSchedule := updater.ScheduleConfig{
		Type:     updater.SchedulerInterval,
		Interval: 200 * time.Millisecond,
	}
	log := logrus.NewEntry(logrus.StandardLogger())
	logrus.SetLevel(logrus.DebugLevel)
	u := updater.NewUpdater(pool, sources.NewDependencytrackSource(dpTrack, log), updateSchedule, log)

	t.Run("images in initialized state should be updated and vulnerabilities fetched", func(t *testing.T) {
		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(1*time.Second))
		defer cancel()

		insertWorkloads(ctx, t, db, projectNames)
		u.Run(updaterCtx)
		time.Sleep(2 * updateSchedule.Interval)

		for _, p := range projectNames {
			imageName := p
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
		}
	})

	t.Run("images older than interval should be marked with resync and vulnerabilities updated", func(t *testing.T) {
		insertWorkloads(ctx, t, db, projectNames)
		_, err := pool.Exec(
			ctx,
			"UPDATE images SET state = $1 WHERE state = $2;",
			sql.ImageStateUpdated,
			sql.ImageStateInitialized,
		)
		assert.NoError(t, err)

		imageLastUpdated := time.Now().Add(-(time.Hour * 24))
		imageName := projectNames[0]
		imageVersion := "v1"
		_, err = pool.Exec(
			ctx,
			"UPDATE images SET updated_at = $1 WHERE name = $2 AND tag=$3;",
			imageLastUpdated,
			imageName,
			imageVersion,
		)
		assert.NoError(t, err)

		dpTrack.AddFinding(imageName, "new-vuln")

		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
		defer cancel()

		// Should update projectName[0] since it is older than updater.DefaultResyncImagesOlderThanMinutes
		u.Run(updaterCtx)
		time.Sleep(2 * updateSchedule.Interval)

		vulns, err := db.ListVulnerabilities(
			ctx,
			sql.ListVulnerabilitiesParams{Limit: 100, ImageName: &imageName, ImageTag: &imageVersion},
		)
		assert.NoError(t, err)
		assert.Len(t, vulns, 5)

		images, err := db.GetImage(ctx, sql.GetImageParams{
			Name: imageName,
			Tag:  imageVersion,
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateUpdated, images.State)
	})

	t.Run("images not in use by any workload should not be marked for resync", func(t *testing.T) {
		insertWorkloads(ctx, t, db, projectNames)
		_, err := pool.Exec(
			ctx,
			"UPDATE images SET state = $1 WHERE state = $2;",
			sql.ImageStateUpdated,
			sql.ImageStateInitialized,
		)
		assert.NoError(t, err)

		for _, p := range projectNames {
			imageLastUpdated := time.Now().Add(-(time.Hour * 24))
			imageName := p
			imageVersion := "v1"
			_, err = pool.Exec(
				ctx,
				"UPDATE images SET updated_at = $1 WHERE name = $2 AND tag=$3;",
				imageLastUpdated,
				imageName,
				imageVersion,
			)
			assert.NoError(t, err)

			_, err = pool.Exec(
				ctx,
				"INSERT into images (name, tag, state) VALUES ($1, $2, $3);",
				imageName,
				"old",
				"updated",
			)
			assert.NoError(t, err)

			err = db.MarkImagesForResync(ctx, sql.MarkImagesForResyncParams{
				ThresholdTime: pgtype.Timestamptz{
					Time:  time.Now().Add(-12 * time.Hour),
					Valid: true,
				},
				ExcludedStates: []sql.ImageState{
					sql.ImageStateResync,
					sql.ImageStateUntracked,
					sql.ImageStateFailed,
				},
			})
			assert.NoError(t, err)

			image, err := db.GetImage(ctx, sql.GetImageParams{
				Name: imageName,
				Tag:  "old",
			})

			assert.NoError(t, err)
			// Should not be marked for resync
			assert.Equal(t, sql.ImageStateUpdated, image.State)

			image, err = db.GetImage(ctx, sql.GetImageParams{
				Name: imageName,
				Tag:  imageVersion,
			})
			assert.NoError(t, err)
			// Should be marked for resync
			assert.Equal(t, sql.ImageStateResync, image.State)
		}
	})
}

func insertWorkloads(ctx context.Context, t *testing.T, db *sql.Queries, projectNames []string) {
	for _, p := range projectNames {
		err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     p,
			Tag:      "v1",
			Metadata: map[string]string{"key": "value"},
		})
		assert.NoError(t, err)

		_, err = db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name:         fmt.Sprintf("workload-%s", p),
			WorkloadType: "app",
			Namespace:    "namespace-1",
			Cluster:      "cluster-1",
			ImageName:    p,
			ImageTag:     "v1",
		})
		if !errors.Is(err, pgx.ErrNoRows) {
			assert.NoError(t, err)
		}
	}
}

var _ dependencytrack.Client = (*MockDtrack)(nil)

type MockDtrack struct {
	projects []*client.Project
	findings map[string][]client.Finding
}

func (m MockDtrack) CreateProject(ctx context.Context, name, version string, tags []client.Tag) (*client.Project, error) {
	panic("implement me")
}

func (m MockDtrack) CreateOrUpdateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, workloadRef *dependencytrack.WorkloadRef) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) UpdateProject(ctx context.Context, project *client.Project) (*client.Project, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) CreateProjectWithSbom(ctx context.Context, sbom *in_toto.CycloneDXStatement, imageName, imageTag string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) DeleteProject(ctx context.Context, uuid string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) UploadSbom(ctx context.Context, projectId string, sbom *in_toto.CycloneDXStatement) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) TriggerAnalysis(ctx context.Context, uuid string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) UpdateFinding(ctx context.Context, suppressedBy, reason, projectId, componentId, vulnerabilityId string, state string, suppressed bool) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetAnalysisTrailForImage(ctx context.Context, projectId, componentId, vulnerabilityId string) (*client.Analysis, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) AddFinding(projectName string, vulnName string) {
	u := ""
	for _, p := range m.projects {
		if *p.Name == projectName {
			u = p.Uuid
		}
	}
	findings := m.findings[u]
	findings = append(findings, client.Finding{
		Component: map[string]interface{}{
			"purl": fmt.Sprintf("pkg:component-%s", vulnName),
		},
		Vulnerability: map[string]interface{}{
			"severity":    "CRITICAL",
			"source":      "NVD",
			"title":       "title",
			"description": "description",
			"vulnId":      fmt.Sprintf("CVE-%s", vulnName),
		},
		Analysis: map[string]interface{}{
			"isSuppressed": false,
		},
	})
	m.findings[u] = findings
}

func (m MockDtrack) GetFindings(ctx context.Context, uuid, vulnerabilityId string, suppressed bool) ([]client.Finding, error) {
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
