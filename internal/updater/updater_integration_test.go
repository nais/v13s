package updater_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/database/typeext"
	"github.com/nais/v13s/internal/kubernetes"
	dependencytrackMock "github.com/nais/v13s/internal/mocks/Client"
	attestation "github.com/nais/v13s/internal/mocks/Verifier"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/postgresriver"
	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUpdater(t *testing.T) {
	ctx := context.Background()

	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	assert.NoError(t, err)

	projectNames := []string{"project-1", "project-2", "project-3", "project-4"}
	mockDPTrack := new(dependencytrackMock.MockClient)
	verifierMock := new(attestation.MockVerifier)

	jobCfg := &riverjob.Options{
		DbUrl: pool.Config().ConnString(),
	}

	queue := &kubernetes.WorkloadEventQueue{
		Updated: make(chan *model.Workload, 100),
		Deleted: make(chan *model.Workload, 100),
	}

	sourceMock := sources.NewDependencytrackSource(mockDPTrack, logrus.NewEntry(logrus.StandardLogger()))

	mgr, err := postgresriver.NewWorkloadManager(ctx, postgresriver.WorkloadManagerConfig{
		Pool:      pool,
		JobConfig: jobCfg,
		Verifier:  verifierMock,
		Source:    sourceMock,
		Queue:     queue,
		Logger:    logrus.NewEntry(logrus.StandardLogger()),
	})

	mgr.Start(ctx)
	defer func() { _ = mgr.Stop(ctx) }()

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

	u := updater.NewUpdater(pool, sources.NewDependencytrackSource(mockDPTrack, log), mgr, updateSchedule, log)

	t.Run("images in initialized state should be updated and vulnerabilities fetched", func(t *testing.T) {
		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(10*time.Second))
		defer cancel()

		insertWorkloads(ctx, t, db, projectNames)
		_, err = pool.Exec(ctx, `
    		UPDATE images
    		SET metadata = '{}', ready_for_resync_at = NOW()
    		WHERE state = 'initialized'`)
		require.NoError(t, err)

		err = u.ResyncImageVulnerabilities(updaterCtx)
		assert.NoError(t, err)

		require.Eventually(t, func() bool {
			for _, p := range projectNames {
				image, err := db.GetImage(ctx, sql.GetImageParams{Name: p, Tag: "v1"})
				if err != nil {
					return false
				}
				if image.State != sql.ImageStateUpdated {
					return false
				}
			}
			return true
		}, 5*time.Second, 100*time.Millisecond)

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
		_, err = pool.Exec(ctx, `
    		UPDATE images
    		SET metadata = '{}', ready_for_resync_at = NOW()
    		WHERE state = 'initialized'`)
		require.NoError(t, err)

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

		u = updater.NewUpdater(pool, sourceMock, mgr, updateSchedule, logrus.NewEntry(logrus.StandardLogger()))
		u.Run(updaterCtx)

		require.Eventually(t, func() bool {
			vulns, err := db.ListVulnerabilities(ctx, sql.ListVulnerabilitiesParams{
				ImageName: &imageName,
				ImageTag:  &imageVersion,
				Limit:     100,
			})
			if err != nil {
				return false
			}
			return len(vulns) == 5
		}, 5*time.Second, 200*time.Millisecond)

		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: imageName,
			Tag:  imageVersion,
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateUpdated, image.State)
	})

	t.Run("images older than threshold should be marked as untracked", func(t *testing.T) {
		err = db.ResetDatabase(ctx)
		assert.NoError(t, err)

		imageName := "project-1"
		imageVersion := "v1"

		insertWorkloads(ctx, t, db, projectNames)

		tx, err := pool.Begin(ctx)
		assert.NoError(t, err)

		// set image state to initialized
		_, err = tx.Exec(ctx,
			"UPDATE images SET state=$1 WHERE name=$2 AND tag=$3",
			sql.ImageStateInitialized, imageName, imageVersion)
		assert.NoError(t, err)

		// set updated_at to 1 hour ago UTC
		imageLastUpdated := time.Now().UTC().Add(-1 * time.Hour)
		_, err = tx.Exec(ctx,
			"UPDATE images SET updated_at=$1 WHERE name=$2 AND tag=$3",
			imageLastUpdated, imageName, imageVersion)
		assert.NoError(t, err)

		err = tx.Commit(ctx)
		assert.NoError(t, err)

		// log current setup
		fmt.Printf("Setup image: %s updated_at=%v\n", imageName, imageLastUpdated)

		// print threshold used by updater
		threshold := time.Now().UTC().Add(-updater.ImageMarkAge)
		fmt.Printf("Threshold for untracking: %v\n", threshold)

		u = updater.NewUpdater(pool, sourceMock, mgr, updateSchedule, logrus.NewEntry(logrus.StandardLogger()))

		err = u.MarkImagesAsUntracked(ctx)
		assert.NoError(t, err)

		// query all images after running updater
		rows, _ := pool.Query(ctx, "SELECT name, state, updated_at FROM images ORDER BY name")
		for rows.Next() {
			var n, s string
			var t time.Time
			rows.Scan(&n, &s, &t)
			fmt.Printf("After updater: row: %s state=%s updated_at=%v older_than_threshold=%v\n",
				n, s, t, t.Before(threshold))
		}

		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: imageName,
			Tag:  imageVersion,
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateUntracked, image.State)
	})

	t.Run("images older than threshold without workloads should be marked as unused", func(t *testing.T) {
		err := db.ResetDatabase(ctx)
		assert.NoError(t, err)

		insertWorkloads(ctx, t, db, []string{"project-2", "project-3"}) // project-1 and project-4 will have no workloads

		// manually insert/update images
		projects := []string{"project-1", "project-2", "project-3", "project-4"}
		for _, p := range projects {
			_, err := pool.Exec(ctx,
				"INSERT INTO images (name, tag, state, updated_at) VALUES ($1, $2, $3, $4) ON CONFLICT (name, tag) DO UPDATE SET state=$3, updated_at=$4;",
				p, "v1", sql.ImageStateInitialized, time.Now().Add(-2*updater.ImageMarkAge),
			)
			assert.NoError(t, err)
		}

		u = updater.NewUpdater(pool, sourceMock, mgr, updateSchedule, logrus.NewEntry(logrus.StandardLogger()))

		err = u.MarkUnusedImages(ctx)
		assert.NoError(t, err)

		// fetch all images and check state
		rows, _ := pool.Query(ctx, "SELECT name, state, updated_at FROM images ORDER BY name")
		defer rows.Close()
		for rows.Next() {
			var name, state string
			var updatedAt time.Time
			rows.Scan(&name, &state, &updatedAt)
			fmt.Printf("row: %s state=%s updated_at=%v\n", name, state, updatedAt)
			switch name {
			case "project-1", "project-4":
				assert.Equal(t, sql.ImageStateUnused, sql.ImageState(state), "image without workload should be unused")
			case "project-2", "project-3":
				assert.Equal(t, sql.ImageStateInitialized, sql.ImageState(state), "image with workload should remain initialized")
			}
		}
	})

	t.Run("images older than threshold should be marked for resync", func(t *testing.T) {
		err = db.ResetDatabase(ctx)
		assert.NoError(t, err)

		imageName := "project-1"
		imageVersion := "v1"
		insertWorkloads(ctx, t, db, projectNames)

		// set image state to something that is not excluded
		_, err = pool.Exec(ctx,
			"UPDATE images SET state = $1 WHERE name = $2 AND tag = $3",
			sql.ImageStateUpdated, imageName, imageVersion)
		assert.NoError(t, err)

		// set updated_at older than threshold
		imageLastUpdated := time.Now().Add(-updater.ResyncImagesOlderThanMinutesDefault - time.Hour)
		_, err = pool.Exec(ctx,
			"UPDATE images SET updated_at = $1 WHERE name = $2 AND tag = $3",
			imageLastUpdated, imageName, imageVersion)
		assert.NoError(t, err)

		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: imageName,
			Tag:  imageVersion,
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateUpdated, image.State)

		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
		defer cancel()

		u := updater.NewUpdater(pool, sourceMock, mgr, updateSchedule, logrus.NewEntry(logrus.StandardLogger()))

		err = u.MarkForResync(updaterCtx)
		assert.NoError(t, err)

		rows, _ := pool.Query(ctx, "SELECT name, state, updated_at FROM images")
		for rows.Next() {
			var n, s string
			var t time.Time
			rows.Scan(&n, &s, &t)
			fmt.Printf("row: %s state=%s updated_at=%v\n", n, s, t)
		}

		// check that project-1 has been updated to 'resync'
		image, err = db.GetImage(ctx, sql.GetImageParams{
			Name: imageName,
			Tag:  imageVersion,
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateResync, image.State)
	})

	t.Run("images ready for resync after SBOM upload", func(t *testing.T) {
		ctx = context.Background()

		err = db.ResetDatabase(ctx)
		assert.NoError(t, err)

		imageName := "project-1"
		imageTag := "v1"

		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     imageName,
			Tag:      imageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		// Set ReadyForResyncAt to 5 minutes ago
		readyAt := time.Now().Add(-5 * time.Minute)
		err = db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  imageName,
			Tag:   imageTag,
			State: sql.ImageStateResync,
			ReadyForResyncAt: pgtype.Timestamptz{
				Time:  readyAt,
				Valid: true,
			},
		})
		assert.NoError(t, err)

		image, err := db.GetImage(ctx, sql.GetImageParams{Name: imageName, Tag: imageTag})
		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateResync, image.State)
		assert.True(t, image.ReadyForResyncAt.Time.Before(time.Now()))

		u = updater.NewUpdater(pool, sourceMock, mgr, updateSchedule, logrus.NewEntry(logrus.StandardLogger()))

		images, err := db.GetImagesScheduledForSync(ctx)
		assert.NoError(t, err)

		// Check that the image is selected for resync
		assert.Len(t, images, 1)
		assert.Equal(t, imageName, images[0].Name)
		assert.Equal(t, imageTag, images[0].Tag)
	})
}

func TestUpdater_DetermineSeveritySince(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	u := updater.NewUpdater(pool, nil, nil, updater.ScheduleConfig{}, logrus.NewEntry(logrus.StandardLogger()))

	imageName := "image-1"
	imageTag := "v1"
	pkg := "pkg-1"
	cveID := "CVE-123"

	querier := sql.New(pool)
	err := querier.CreateImage(ctx, sql.CreateImageParams{
		Name:     imageName,
		Tag:      imageTag,
		Metadata: map[string]string{},
	})
	require.NoError(t, err)

	querier.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{
		{
			CveID:    cveID,
			CveTitle: "Test title",
			CveDesc:  "Test description",
			CveLink:  "https://example.com",
			Severity: 2,
			Refs:     typeext.MapStringString{},
		},
	}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})

	querier.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
		{
			ImageName:     imageName,
			ImageTag:      imageTag,
			Package:       pkg,
			CveID:         cveID,
			Source:        "source",
			LatestVersion: "1.0",
			LastSeverity:  2,
			SeveritySince: pgtype.Timestamptz{Valid: false, Time: time.Time{}},
		},
	}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})

	t.Run("returns earliest severity_since if set", func(t *testing.T) {
		ts := time.Now().Add(-1 * time.Hour)
		_, err := pool.Exec(ctx, `
            UPDATE vulnerabilities
            SET severity_since = $1, last_severity = $2
            WHERE image_name = $3 AND package = $4 AND cve_id = $5
        `, ts, 2, imageName, pkg, cveID)
		require.NoError(t, err)

		got, err := u.DetermineSeveritySince(ctx, imageName, pkg, cveID, 2)
		require.NoError(t, err)
		assert.NotNil(t, got)
		assert.WithinDuration(t, ts, *got, time.Second)
	})

	t.Run("returns timestamp if severity not present", func(t *testing.T) {
		got, err := u.DetermineSeveritySince(ctx, imageName, pkg, cveID, 5)
		require.NoError(t, err)
		assert.NotNil(t, got)
	})

	t.Run("does not overwrite existing severity_since", func(t *testing.T) {
		ts := time.Now().UTC().Add(-1 * time.Hour)
		_, err := pool.Exec(ctx, `
        UPDATE vulnerabilities
        SET severity_since = $1, last_severity = 2
        WHERE image_name = $2 AND package = $3 AND cve_id = $4
    `, ts, imageName, pkg, cveID)
		require.NoError(t, err)

		got, err := u.DetermineSeveritySince(ctx, imageName, pkg, cveID, 2)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.WithinDuration(t, ts, (*got).UTC(), 1*time.Second)
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
