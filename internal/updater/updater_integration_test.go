package updater_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	dependencytrackMock "github.com/nais/v13s/mocks/github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
	mockDPTrack := new(dependencytrackMock.MockClient)

	for _, project := range projectNames {
		mockDPTrack.On("GetProject", mock.Anything, project, "v1").Return(&dependencytrack.Project{
			Name:    project,
			Uuid:    project,
			Version: "v1",
			Metrics: &dependencytrack.ProjectMetric{
				Critical:           1,
				High:               2,
				Medium:             3,
				Low:                4,
				Unassigned:         5,
				InheritedRiskScore: 6.0,
			},
		}, nil)
	}

	findings := map[string][]*dependencytrack.Vulnerability{}

	// Return 4 vulns per image for initial test
	mockDPTrack.On("GetFindings", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("bool"), mock.Anything).
		Return(func(ctx context.Context, uuid string, suppressed bool, filterSource ...string) ([]*dependencytrack.Vulnerability, error) {
			if vulns, ok := findings[uuid]; ok {
				return vulns, nil
			}
			// fallback: return default 4 vulns
			vulns := make([]*dependencytrack.Vulnerability, 4)
			for i := 0; i < 4; i++ {
				vulns[i] = &dependencytrack.Vulnerability{
					Package: "pkg:component-" + uuid + fmt.Sprintf("-%d", i),
					Cve: &dependencytrack.Cve{
						Description: "description",
						Title:       "title",
						Link:        fmt.Sprintf("mylink-%s-%d", uuid, i),
						Severity:    "CRITICAL",
						Id:          fmt.Sprintf("CVE-%s-%d", uuid, i),
						References:  map[string]string{"ref": fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-%s-%d", uuid, i)},
					},
					Metadata: &dependencytrack.VulnMetadata{
						ProjectId:         uuid,
						ComponentId:       fmt.Sprintf("component-%s-%d", uuid, i),
						VulnerabilityUuid: fmt.Sprintf("vuln-%s-%d", uuid, i),
					},
				}
			}
			return vulns, nil
		})

	updateSchedule := updater.ScheduleConfig{
		Type:     updater.SchedulerInterval,
		Interval: 200 * time.Millisecond,
	}
	log := logrus.NewEntry(logrus.StandardLogger())
	logrus.SetLevel(logrus.DebugLevel)

	done := make(chan struct{})
	u := updater.NewUpdater(pool, sources.NewDependencytrackSource(mockDPTrack, log), updateSchedule, done, log)

	t.Run("images in initialized state should be updated and vulnerabilities fetched", func(t *testing.T) {
		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(10*time.Second))
		defer cancel()

		insertWorkloads(ctx, t, db, projectNames)
		err = u.ResyncImageVulnerabilities(updaterCtx)
		assert.NoError(t, err)

		select {
		case <-done:
			// proceed with asserts
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for updater to complete")
		}

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
			assert.Len(t, vulns, 4) // Matches the 4 vulns from mock

			assert.True(t, collections.AnyMatch(vulns, func(r *sql.ListVulnerabilitiesRow) bool {
				return r.ImageName == imageName && r.ImageTag == imageTag && r.CveID == fmt.Sprintf("CVE-%s-0", imageName)
			}))
		}
	})

	t.Run("images older than interval should be marked with resync and vulnerabilities updated", func(t *testing.T) {
		err = db.ResetDatabase(ctx)
		assert.NoError(t, err)

		insertWorkloads(ctx, t, db, projectNames)
		_, err = pool.Exec(
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

		// range from 1 to 5 to simulate 5 vulns
		for i := 1; i <= 5; i++ {
			cveID := fmt.Sprintf("CVE-%s-%d", imageName, i)
			addFinding(findings, projectNames[0], cveID)
		}

		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
		defer cancel()

		done = make(chan struct{})
		u = updater.NewUpdater(pool, sources.NewDependencytrackSource(mockDPTrack, logrus.NewEntry(logrus.StandardLogger())), updateSchedule, done, logrus.NewEntry(logrus.StandardLogger()))
		u.Run(updaterCtx)

		select {
		case <-done:
			// proceed with asserts
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for updater to complete")
		}

		vulns, err := db.ListVulnerabilities(
			ctx,
			sql.ListVulnerabilitiesParams{Limit: 100, ImageName: &imageName, ImageTag: &imageVersion},
		)
		assert.NoError(t, err)
		assert.Len(t, vulns, 5)

		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: imageName,
			Tag:  imageVersion,
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateUpdated, image.State)
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

func addFinding(findings map[string][]*dependencytrack.Vulnerability, projectUUID, cveID string) {
	findings[projectUUID] = append(findings[projectUUID], &dependencytrack.Vulnerability{
		Suppressed:    false,
		LatestVersion: "123",
		Metadata: &dependencytrack.VulnMetadata{
			ProjectId:         projectUUID,
			ComponentId:       fmt.Sprintf("component-%s", cveID),
			VulnerabilityUuid: fmt.Sprintf("vuln-%s", cveID),
		},
		Cve: &dependencytrack.Cve{
			Id:          fmt.Sprintf("CVE-%s", cveID),
			Description: "description",
			Title:       "title",
			Link:        fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-%s", cveID),
			Severity:    "CRITICAL",
			References:  map[string]string{},
		},
		Package: fmt.Sprintf("pkg:component-%s", cveID),
	})
}
