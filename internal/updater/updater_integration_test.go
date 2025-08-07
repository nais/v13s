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
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/nais/dependencytrack/pkg/dependencytrack/auth"
	"github.com/nais/dependencytrack/pkg/dependencytrack/client"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
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
	projects        []*dependencytrack.Project
	vulnerabilities map[string][]*dependencytrack.Vulnerability
}

func (m MockDtrack) CreateProjectWithSbom(ctx context.Context, imageName, imageTag string, sbom []byte) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetFindings(ctx context.Context, uuid string, suppressed bool, filterSource ...string) ([]*dependencytrack.Vulnerability, error) {
	for _, p := range m.projects {
		if p.Uuid == uuid {
			if findings, ok := m.vulnerabilities[uuid]; ok {
				return findings, nil
			}
			return nil, fmt.Errorf("no vulnerabilities found for project with uuid %s", uuid)
		}
	}
	return nil, fmt.Errorf("project not found with uuid %s", uuid)
}

func (m MockDtrack) AddToTeam(ctx context.Context, username, uuid string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) AllMetricsRefresh(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) ChangeAdminPassword(ctx context.Context, oldPassword, newPassword auth.Password) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) ConfigPropertyAggregate(ctx context.Context, property dependencytrack.ConfigProperty) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) CreateAdminUser(ctx context.Context, username string, password auth.Password, teamUuid string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) CreateAdminUsers(ctx context.Context, users []*dependencytrack.AdminUser, teamUuid string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) CreateOidcUser(ctx context.Context, email string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) CreateProject(ctx context.Context, imageName, imageTag string, tags []string) (*dependencytrack.Project, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) CreateTeam(ctx context.Context, teamName string, permissions []dependencytrack.Permission) (*dependencytrack.Team, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) DeleteManagedUser(ctx context.Context, username string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) DeleteOidcUser(ctx context.Context, username string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) DeleteTeam(ctx context.Context, uuid string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) DeleteUserMembership(ctx context.Context, teamUuid, username string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GenerateApiKey(ctx context.Context, uuid string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetAnalysisTrailForImage(ctx context.Context, projectId, componentId, vulnerabilityId string) (*dependencytrack.Analysis, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetConfigProperties(ctx context.Context) ([]dependencytrack.ConfigProperty, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetEcosystems(ctx context.Context) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetVulnerabilities(ctx context.Context, uuid, vulnerabilityId string, suppressed bool) ([]*dependencytrack.Vulnerability, error) {
	for _, p := range m.projects {
		if p.Uuid == uuid {
			return m.vulnerabilities[uuid], nil
		}
	}
	return nil, fmt.Errorf("project not found")
}

func (m MockDtrack) GetOidcUser(ctx context.Context, username string) (*dependencytrack.User, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetOidcUsers(ctx context.Context) ([]*dependencytrack.User, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetTeam(ctx context.Context, team string) (*dependencytrack.Team, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) GetTeams(ctx context.Context) ([]*dependencytrack.Team, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) ProjectMetricsRefresh(ctx context.Context, uuid string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) RemoveAdminUser(ctx context.Context, username string) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) RemoveAdminUsers(ctx context.Context, users []*dependencytrack.AdminUser) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) UpdateFinding(ctx context.Context, request dependencytrack.AnalysisRequest) error {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) Version(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) AuthContext(ctx context.Context) (context.Context, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) Login(ctx context.Context, username, password string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m MockDtrack) UpdateProject(ctx context.Context, project *client.Project) (*client.Project, error) {
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

func (m MockDtrack) AddFinding(projectName string, vulnName string) {
	u := ""
	for _, p := range m.projects {
		if p.Name == projectName {
			u = p.Uuid
		}
	}
	findings := m.vulnerabilities[u]
	findings = append(findings, &dependencytrack.Vulnerability{
		Suppressed:    false,
		LatestVersion: "123",
		Metadata:      &dependencytrack.VulnMetadata{},
		Cve: &dependencytrack.Cve{
			Id:          fmt.Sprintf("CVE-%s", vulnName),
			Description: "description",
			Title:       "title",
			Link:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-%s", vulnName),
			Severity:    "CRITICAL",
			References:  map[string]string{},
		},
		Package: fmt.Sprintf("pkg:component-%s", vulnName),
	})
	m.vulnerabilities[u] = findings
}

func (m MockDtrack) GetProject(ctx context.Context, name, version string) (*dependencytrack.Project, error) {
	for _, p := range m.projects {
		if p.Name == name && p.Version == version {
			return p, nil
		}
	}
	return nil, fmt.Errorf("project not found")
}

func (m MockDtrack) GetProjects(ctx context.Context, limit, offset int32) ([]dependencytrack.Project, error) {
	//TODO implement me
	panic("implement me")
}

func NewMock(projectNames []string) *MockDtrack {
	mapFindings := make(map[string][]*dependencytrack.Vulnerability)

	projects := make([]*dependencytrack.Project, 0)

	for _, p := range projectNames {
		id := uuid.New().String()
		critical := int32(1)
		high := int32(2)
		medium := int32(3)
		low := int32(4)
		unassigned := int32(5)
		riskScore := float64(6)
		version := "v1"

		projects = append(projects, &dependencytrack.Project{
			Name:    p,
			Version: version,
			Uuid:    id,
			Metrics: &dependencytrack.ProjectMetric{
				Critical:           critical,
				High:               high,
				Medium:             medium,
				Low:                low,
				Unassigned:         unassigned,
				InheritedRiskScore: riskScore,
			},
		})

		findings := make([]*dependencytrack.Vulnerability, 0)
		for j := 0; j < 4; j++ {
			findings = append(findings, &dependencytrack.Vulnerability{
				Suppressed:    false,
				LatestVersion: "123",
				Metadata:      &dependencytrack.VulnMetadata{},
				Cve: &dependencytrack.Cve{
					Id:          fmt.Sprintf("CVE-%s-%d", p, j),
					Description: "description",
					Title:       "title",
					Link:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-%s-%d", p, j),
					Severity:    "CRITICAL",
					References:  map[string]string{},
				},
				Package: fmt.Sprintf("pkg:component-%d", j),
			})
		}
		mapFindings[id] = findings
	}

	return &MockDtrack{
		projects:        projects,
		vulnerabilities: mapFindings,
	}
}
