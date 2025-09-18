package updater_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/database/typeext"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/manager"
	dependencytrackMock "github.com/nais/v13s/internal/mocks/Client"
	sources2 "github.com/nais/v13s/internal/mocks/Source"
	attestation "github.com/nais/v13s/internal/mocks/Verifier"
	"github.com/nais/v13s/internal/model"
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
	mockSource := new(sources2.MockSource)
	verifierMock := new(attestation.MockVerifier)

	jobCfg := &job.Config{
		DbUrl: pool.Config().ConnString(),
	}

	queue := &kubernetes.WorkloadEventQueue{
		Updated: make(chan *model.Workload, 100),
		Deleted: make(chan *model.Workload, 100),
	}

	mgr := manager.NewWorkloadManager(
		ctx,
		pool,
		jobCfg,
		verifierMock,
		mockSource,
		queue,
		logrus.NewEntry(logrus.StandardLogger()))

	mgr.Start(ctx)
	defer mgr.Stop(ctx)

	for _, p := range projectNames {

		vulns := make([]*sources.Vulnerability, 4)
		for i := 0; i < 4; i++ {
			vulns[i] = &sources.Vulnerability{
				Package: "pkg:component-" + p + fmt.Sprintf("-%d", i),
				Cve: &sources.Cve{
					Description: "description",
					Title:       "title",
					Link:        fmt.Sprintf("mylink-%s-%d", p, i),
					Severity:    "CRITICAL",
					Id:          fmt.Sprintf("CVE-%s-%d", p, i),
					References:  map[string]string{"ref": fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-%s-%d", p, i)},
				},
				Metadata: &dependencytrack.VulnMetadata{
					ProjectId:         p,
					ComponentId:       fmt.Sprintf("component-%s-%d", p, i),
					VulnerabilityUuid: fmt.Sprintf("vuln-%s-%d", p, i),
				},
			}
		}
		mockSource.On(
			"GetVulnerabilities",
			mock.Anything, // context
			p,             // image name
			"v1",          // image version
			true,          // includeFixes
		).Return(vulns, nil)

		mockSource.On("Name").Return("test-source")

		mockSource.On("GetVulnerabilitySummary", mock.Anything, p, "v1").Return(&sources.VulnerabilitySummary{
			Id:         p,
			Critical:   1,
			High:       2,
			Medium:     3,
			Low:        4,
			RiskScore:  6,
			Unassigned: 5,
		}, nil)
	}

	mockSource.On("MaintainSuppressedVulnerabilities", mock.Anything, mock.Anything).
		Return(nil)

	updateSchedule := updater.ScheduleConfig{
		Type:     updater.SchedulerInterval,
		Interval: 200 * time.Millisecond,
	}
	log := logrus.NewEntry(logrus.StandardLogger())
	logrus.SetLevel(logrus.DebugLevel)

	//done := make(chan struct{})
	u := updater.NewUpdater(pool, mockSource, updateSchedule, mgr, log)

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

		for _, p := range projectNames {
			imageName := p
			imageTag := "v1"

			require.Eventually(t, func() bool {
				for _, p = range projectNames {
					img, _ := db.GetImage(ctx, sql.GetImageParams{Name: p, Tag: "v1"})
					if img.State != sql.ImageStateUpdated {
						return false
					}
				}
				return true
			}, 5*time.Second, 100*time.Millisecond)
			assert.NoError(t, err)

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

		updaterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
		defer cancel()

		err = u.MarkForResync(updaterCtx)
		assert.NoError(t, err)
		err = u.ResyncImageVulnerabilities(updaterCtx)
		assert.NoError(t, err)

		var vulnCount int
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM vulnerabilities WHERE image_name=$1 AND image_tag=$2", imageName, imageVersion).Scan(&vulnCount)
		require.NoError(t, err)
		t.Logf("Raw vulnerabilities in DB for %s:%s = %d", imageName, imageVersion, vulnCount)

		rows, _ := pool.Query(ctx, "SELECT image_name, image_tag, cve_id FROM vulnerabilities WHERE image_name=$1 AND image_tag=$2", imageName, imageVersion)
		defer rows.Close()
		for rows.Next() {
			var n, t, cve string
			rows.Scan(&n, &t, &cve)
			fmt.Printf("Found vuln: %s:%s -> %s", n, t, cve)
		}

		rows2, _ := pool.Query(ctx, "SELECT name, image_name, image_tag FROM workloads")
		defer rows2.Close()
		for rows2.Next() {
			var wn, in, it string
			rows2.Scan(&wn, &in, &it)
			t.Logf("Workload row: name=%s image=%s:%s", wn, in, it)
		}

		require.Eventually(t, func() bool {
			image, _ := db.GetImage(ctx, sql.GetImageParams{Name: imageName, Tag: imageVersion})
			vulns, _ := db.ListVulnerabilities(ctx, sql.ListVulnerabilitiesParams{
				ImageName: &imageName,
				ImageTag:  &imageVersion,
				Offset:    0,
				Limit:     100,
			})
			t.Logf("Image %s:%s state=%s updated_at=%v, vulns=%d",
				imageName, imageVersion, image.State, image.UpdatedAt, len(vulns))
			return image.State == sql.ImageStateUpdated || image.State == sql.ImageStateResync && len(vulns) == 4
		}, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("images older than threshold should be marked as untracked", func(t *testing.T) {
		err = db.ResetDatabase(ctx)
		assert.NoError(t, err)

		imageName := "project-1"
		imageVersion := "v1"

		insertWorkloads(ctx, t, db, projectNames)

		tx, err := pool.Begin(ctx)
		assert.NoError(t, err)

		_, err = tx.Exec(ctx,
			"UPDATE images SET state=$1 WHERE name=$2 AND tag=$3",
			sql.ImageStateInitialized, imageName, imageVersion)
		assert.NoError(t, err)

		imageLastUpdated := time.Now().UTC().Add(-1 * time.Hour)
		_, err = tx.Exec(ctx,
			"UPDATE images SET updated_at=$1 WHERE name=$2 AND tag=$3",
			imageLastUpdated, imageName, imageVersion)
		assert.NoError(t, err)

		err = tx.Commit(ctx)
		assert.NoError(t, err)

		fmt.Printf("Setup image: %s updated_at=%v\n", imageName, imageLastUpdated)

		threshold := time.Now().UTC().Add(-updater.ImageMarkAge)
		fmt.Printf("Threshold for untracking: %v\n", threshold)

		u = updater.NewUpdater(pool, sources.NewDependencytrackSource(mockDPTrack, logrus.NewEntry(logrus.StandardLogger())), updateSchedule, mgr, logrus.NewEntry(logrus.StandardLogger()))

		err = u.MarkImagesAsUntracked(ctx)
		assert.NoError(t, err)

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

		projects := []string{"project-1", "project-2", "project-3", "project-4"}
		for _, p := range projects {
			_, err := pool.Exec(ctx,
				"INSERT INTO images (name, tag, state, updated_at) VALUES ($1, $2, $3, $4) ON CONFLICT (name, tag) DO UPDATE SET state=$3, updated_at=$4;",
				p, "v1", sql.ImageStateInitialized, time.Now().Add(-2*updater.ImageMarkAge),
			)
			assert.NoError(t, err)
		}

		u = updater.NewUpdater(pool, sources.NewDependencytrackSource(mockDPTrack, logrus.NewEntry(logrus.StandardLogger())), updateSchedule, mgr, logrus.NewEntry(logrus.StandardLogger()))

		err = u.MarkUnusedImages(ctx)
		assert.NoError(t, err)

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

		_, err = pool.Exec(ctx,
			"UPDATE images SET state = $1 WHERE name = $2 AND tag = $3",
			sql.ImageStateUpdated, imageName, imageVersion)
		assert.NoError(t, err)

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

		u := updater.NewUpdater(pool, sources.NewDependencytrackSource(mockDPTrack, logrus.NewEntry(logrus.StandardLogger())), updateSchedule, mgr, logrus.NewEntry(logrus.StandardLogger()))

		err = u.MarkForResync(updaterCtx)
		assert.NoError(t, err)

		rows, _ := pool.Query(ctx, "SELECT name, state, updated_at FROM images")
		for rows.Next() {
			var n, s string
			var t time.Time
			rows.Scan(&n, &s, &t)
			fmt.Printf("row: %s state=%s updated_at=%v\n", n, s, t)
		}

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

		readyAt := time.Now().Add(-manager.FinalizeAttestationScheduledForResyncMinutes)
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

		u = updater.NewUpdater(pool, sources.NewDependencytrackSource(mockDPTrack, logrus.NewEntry(logrus.StandardLogger())), updateSchedule, mgr, logrus.NewEntry(logrus.StandardLogger()))

		images, err := db.GetImagesScheduledForSync(ctx)
		assert.NoError(t, err)

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

		got, err := manager.DetermineSeveritySince(ctx, db, imageName, pkg, cveID, 2)
		require.NoError(t, err)
		assert.NotNil(t, got)
		assert.WithinDuration(t, ts, *got, time.Second)
	})

	t.Run("returns timestamp if severity not present", func(t *testing.T) {
		got, err := manager.DetermineSeveritySince(ctx, db, imageName, pkg, cveID, 5)
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

		got, err := manager.DetermineSeveritySince(ctx, db, imageName, pkg, cveID, 2)
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

func TestUpdater_SyncWorkloadVulnerabilities(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	imageName := "image-1"
	imageTag := "v1"
	pkg := "pkg-1"
	cveID := "CVE-123"
	severity := int32(2)

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
			Severity: severity,
			Refs:     typeext.MapStringString{},
		},
	}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})

	workload1 := uuid.New()
	workload2 := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO workloads (id, name, cluster, namespace, workload_type, image_name, image_tag, created_at)
		VALUES
		($1, 'workload-1', 'test', 'default', 'deployment', $2, $3, NOW()),
		($4, 'workload-2', 'test', 'default', 'deployment', $2, $3, NOW())
	`, workload1, imageName, imageTag, workload2)
	require.NoError(t, err)

	querier.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
		{
			ImageName:     imageName,
			ImageTag:      imageTag,
			Package:       pkg,
			CveID:         cveID,
			Source:        "source",
			LatestVersion: "1.0",
			LastSeverity:  severity,
			SeveritySince: pgtype.Timestamptz{Valid: false, Time: time.Time{}}, // defaults to NOW()
		},
	}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})

	t.Run("updates SeveritySince only when severity changes", func(t *testing.T) {
		newSeverity := int32(3)
		querier.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
			{
				ImageName:     imageName,
				ImageTag:      imageTag,
				Package:       pkg,
				CveID:         cveID,
				Source:        "source",
				LatestVersion: "1.0",
				LastSeverity:  newSeverity,
				SeveritySince: pgtype.Timestamptz{Valid: false, Time: time.Time{}},
			},
		}).Exec(func(i int, err error) {
			require.NoError(t, err)
		})

		var severitySince time.Time
		err := pool.QueryRow(ctx, `
			SELECT severity_since
			FROM vulnerabilities
			WHERE image_name = $1 AND package = $2 AND cve_id = $3
		`, imageName, pkg, cveID).Scan(&severitySince)
		require.NoError(t, err)

		assert.WithinDuration(t, time.Now(), severitySince, 5*time.Second)
	})
}
