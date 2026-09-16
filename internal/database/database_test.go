package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkImagesAsUnused(t *testing.T) {
	ctx := context.Background()

	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("image used by workload should not be marked as unused", func(t *testing.T) {
		createTestdata(t, db, "testimage1", "v1", true)

		affectedRows, err := db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time:  time.Now().Add(-updater.ImageMarkAge),
					Valid: true,
				},
				ExcludedStates: []sql.ImageState{
					sql.ImageStateResync,
					sql.ImageStateFailed,
				},
			})
		assert.NoError(t, err)
		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage1",
			Tag:  "v1",
		})
		assert.NoError(t, err)
		assert.Equal(t, int64(0), affectedRows)
		assert.NotEqual(t, sql.ImageStateUnused, image.State)
	})

	t.Run("image with resync state should not be marked as unused", func(t *testing.T) {
		createTestdata(t, db, "testimage2", "v1", true)

		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage2",
			Tag:  "v1",
		})
		assert.NoError(t, err)

		_, err = db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  image.Name,
			Tag:   image.Tag,
			State: sql.ImageStateResync,
		})
		assert.NoError(t, err)

		affectedRows, err := db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time:  time.Now().Add(-updater.ImageMarkAge),
					Valid: true,
				},
				ExcludedStates: []sql.ImageState{
					sql.ImageStateResync,
					sql.ImageStateFailed,
				},
			})
		assert.NoError(t, err)

		image, err = db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage2",
			Tag:  "v1",
		})
		assert.NoError(t, err)
		assert.Equal(t, int64(0), affectedRows)
		assert.NotEqual(t, sql.ImageStateUnused, image.State)
	})

	t.Run("image without workload should be marked as unused", func(t *testing.T) {
		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     "testimage",
			Tag:      "old",
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		affectedRows, err := db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time:  time.Now().Add(1 * time.Minute),
					Valid: true,
				},
				ExcludedStates: []sql.ImageState{
					sql.ImageStateResync,
					sql.ImageStateFailed,
				},
			})
		assert.NoError(t, err)
		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage",
			Tag:  "old",
		})

		assert.NoError(t, err)
		assert.Equal(t, int64(1), affectedRows)
		assert.Equal(t, sql.ImageStateUnused, image.State)
	})
}

func TestDeleteUnusedSourceRefs(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	imageName := "testimage-srcref"
	imageTagUnused := "unused"
	imageTagUsed := "used"

	assert.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: imageName, Tag: imageTagUnused, Metadata: map[string]string{}}))
	assert.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: imageName, Tag: imageTagUsed, Metadata: map[string]string{}}))

	_, err = db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         "wl1",
		WorkloadType: "application",
		Namespace:    "test",
		Cluster:      "test",
		ImageName:    imageName,
		ImageTag:     imageTagUsed,
	})
	assert.NoError(t, err)

	srcUnusedID := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	srcUsedID := pgtype.UUID{Bytes: uuid.New(), Valid: true}

	assert.NoError(t, db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
		SourceID:   srcUnusedID,
		SourceType: "dependencytrack",
		ImageName:  imageName,
		ImageTag:   imageTagUnused,
	}))

	assert.NoError(t, db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
		SourceID:   srcUsedID,
		SourceType: "dependencytrack",
		ImageName:  imageName,
		ImageTag:   imageTagUsed,
	}))

	rows, err := db.ListUnusedSourceRefs(ctx, &imageName)
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, imageTagUnused, rows[0].ImageTag)

	err = db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTagUnused,
		SourceType: "dependencytrack",
	})
	assert.NoError(t, err)

	err = db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTagUnused,
		SourceType: "dependencytrack",
	})
	assert.NoError(t, err)

	rowsAfter, err := db.ListUnusedSourceRefs(ctx, &imageName)
	assert.NoError(t, err)
	assert.Len(t, rowsAfter, 0)

	srcUsed, err := db.GetSourceRef(ctx, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTagUsed,
		SourceType: "dependencytrack",
	})
	assert.NoError(t, err)
	assert.Equal(t, imageTagUsed, srcUsed.ImageTag)
}

func createTestdata(t *testing.T, db sql.Querier, image_name, image_tag string, createWorkload bool) {
	ctx := context.Background()
	err := db.CreateImage(ctx, sql.CreateImageParams{
		Name:     image_name,
		Tag:      image_tag,
		Metadata: map[string]string{},
	})
	assert.NoError(t, err)

	if !createWorkload {
		return
	}
	_, err = db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         image_name,
		WorkloadType: "application",
		Namespace:    "testnamespace1",
		Cluster:      "testcluster1",
		ImageName:    image_name,
		ImageTag:     image_tag,
	})
	assert.NoError(t, err)
}

func TestInitializeWorkload_Failed_Skipped(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	createTestdata(t, db, "img-fail", "v1", false)

	_, err := db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         "wl-fail",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
		ImageName:    "img-fail",
		ImageTag:     "v1",
	})
	require.NoError(t, err)

	wl, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
		Name:         "wl-fail",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
	})
	require.NoError(t, err)
	err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateFailed,
		ID:    wl.ID,
	})
	require.NoError(t, err)

	result, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
		Name:         "wl-fail",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
		ImageName:    "img-fail",
		ImageTag:     "v1",
	})
	assert.NoError(t, err)
	assert.False(t, result.Valid, "InitializeWorkload should not update a failed workload")

	wl2, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
		Name:         "wl-fail",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
	})
	require.NoError(t, err)
	assert.Equal(t, sql.WorkloadStateFailed, wl2.State, "workload state should remain failed")
}

func TestInitializeWorkload_Updated_Skipped(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	createTestdata(t, db, "img-updated", "v1", false)

	_, err := db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         "wl-updated",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
		ImageName:    "img-updated",
		ImageTag:     "v1",
	})
	require.NoError(t, err)

	wl, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
		Name:         "wl-updated",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
	})
	require.NoError(t, err)
	err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateUpdated,
		ID:    wl.ID,
	})
	require.NoError(t, err)

	result, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
		Name:         "wl-updated",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
		ImageName:    "img-updated",
		ImageTag:     "v1",
	})
	assert.NoError(t, err)
	assert.False(t, result.Valid, "InitializeWorkload should not update an already-updated workload with the same image")
}

func TestInitializeWorkload_NoAttestation_Skipped(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	createTestdata(t, db, "img-noatt", "v1", false)

	_, err := db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         "wl-noatt",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
		ImageName:    "img-noatt",
		ImageTag:     "v1",
	})
	require.NoError(t, err)

	wl, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
		Name:         "wl-noatt",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
	})
	require.NoError(t, err)
	err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateNoAttestation,
		ID:    wl.ID,
	})
	require.NoError(t, err)

	result, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
		Name:         "wl-noatt",
		WorkloadType: "application",
		Namespace:    "ns",
		Cluster:      "cl",
		ImageName:    "img-noatt",
		ImageTag:     "v1",
	})
	assert.NoError(t, err)
	assert.False(t, result.Valid, "InitializeWorkload should not update a no_attestation workload with the same image")
}

func TestUpdateWorkloadStateByImage_RecoverNoAttestation(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	createTestdata(t, db, "img-recover", "v1", false)

	_, err := db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         "wl-recover",
		WorkloadType: "app",
		Namespace:    "ns",
		Cluster:      "cl",
		ImageName:    "img-recover",
		ImageTag:     "v1",
	})
	require.NoError(t, err)

	wl, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
		Name:         "wl-recover",
		WorkloadType: "app",
		Namespace:    "ns",
		Cluster:      "cl",
	})
	require.NoError(t, err)

	// Simulate race: workload was set to no_attestation (e.g. lost the timing race)
	err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateNoAttestation,
		ID:    wl.ID,
	})
	require.NoError(t, err)

	// Image is later updated (attestation found by another cluster, or vuln scan completed)
	err = db.UpdateWorkloadStateByImage(ctx, sql.UpdateWorkloadStateByImageParams{
		ImageName: "img-recover",
		ImageTag:  "v1",
		State:     sql.WorkloadStateUpdated,
	})
	require.NoError(t, err)

	recovered, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
		Name:         "wl-recover",
		WorkloadType: "app",
		Namespace:    "ns",
		Cluster:      "cl",
	})
	require.NoError(t, err)
	assert.Equal(t, sql.WorkloadStateUpdated, recovered.State,
		"no_attestation workload should be recovered when image state is updated")
}

func upsertTestCve(t *testing.T, db sql.Querier, ctx context.Context, cveID string) {
	t.Helper()
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{
		{CveID: cveID, CveTitle: "t", CveDesc: "d", CveLink: "l", Severity: 1, Refs: map[string]string{}},
	}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})
}

func TestGetVulnerabilitiesForOsvEnrichment_ExcludesUnsupportedRows(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	createTestdata(t, db, "img-osv", "v1", false)

	for _, cveID := range []string{"CVE-APK-1", "CVE-DEB-1", "CVE-NPM-1", ""} {
		upsertTestCve(t, db, ctx, cveID)
	}

	db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
		{ImageName: "img-osv", ImageTag: "v1", Package: "pkg:apk/wolfi/openssl@3.0.0", CveID: "CVE-APK-1", Source: "test", LastSeverity: 1, SeveritySince: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ImageName: "img-osv", ImageTag: "v1", Package: "pkg:deb/debian/openssl@3.0.0", CveID: "CVE-DEB-1", Source: "test", LastSeverity: 1, SeveritySince: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ImageName: "img-osv", ImageTag: "v1", Package: "pkg:npm/leftpad@1.0.0", CveID: "CVE-NPM-1", Source: "test", LastSeverity: 1, SeveritySince: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ImageName: "img-osv", ImageTag: "v1", Package: "pkg:npm/broken@1.0.0", CveID: "", Source: "test", LastSeverity: 1, SeveritySince: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
	}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})

	rows, err := db.GetVulnerabilitiesForOsvEnrichment(ctx)
	require.NoError(t, err)

	var got []string
	for _, r := range rows {
		got = append(got, r.CveID+"|"+r.Package)
	}
	assert.ElementsMatch(t, []string{"CVE-NPM-1|pkg:npm/leftpad@1.0.0"}, got,
		"apk, deb and empty-cve_id rows must be excluded; only the supported npm pair should remain")
}

func TestBulkUpdateAndClearFixVersions_ScopedToCvePackagePair(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	createTestdata(t, db, "img-a", "v1", false)
	createTestdata(t, db, "img-b", "v1", false)

	upsertTestCve(t, db, ctx, "CVE-SHARED-1")
	upsertTestCve(t, db, ctx, "CVE-OTHER-1")

	db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
		// Same (cve_id, package) pair, two different images — both must move together.
		{ImageName: "img-a", ImageTag: "v1", Package: "pkg:npm/shared-lib@1.0.0", CveID: "CVE-SHARED-1", Source: "test", LastSeverity: 1, SeveritySince: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		{ImageName: "img-b", ImageTag: "v1", Package: "pkg:npm/shared-lib@1.0.0", CveID: "CVE-SHARED-1", Source: "test", LastSeverity: 1, SeveritySince: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
		// Unrelated pair that must never be touched by the calls below.
		{ImageName: "img-a", ImageTag: "v1", Package: "pkg:npm/other-lib@1.0.0", CveID: "CVE-OTHER-1", Source: "test", LastSeverity: 1, SeveritySince: pgtype.Timestamptz{Time: time.Now(), Valid: true}},
	}).Exec(func(i int, err error) {
		require.NoError(t, err)
	})

	getFixVersion := func(imageName, cveID, pkg string) *string {
		v, err := db.GetVulnerability(ctx, sql.GetVulnerabilityParams{
			ImageName: imageName, ImageTag: "v1", CveID: cveID, Package: pkg,
		})
		require.NoError(t, err)
		return v.FixVersion
	}

	n, err := db.BulkUpdateFixVersions(ctx, sql.BulkUpdateFixVersionsParams{
		CveIds:      []string{"CVE-SHARED-1"},
		Packages:    []string{"pkg:npm/shared-lib@1.0.0"},
		FixVersions: []string{"2.0.0"},
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "update must touch both rows sharing the pair")

	require.NotNil(t, getFixVersion("img-a", "CVE-SHARED-1", "pkg:npm/shared-lib@1.0.0"))
	assert.Equal(t, "2.0.0", *getFixVersion("img-a", "CVE-SHARED-1", "pkg:npm/shared-lib@1.0.0"))
	require.NotNil(t, getFixVersion("img-b", "CVE-SHARED-1", "pkg:npm/shared-lib@1.0.0"))
	assert.Equal(t, "2.0.0", *getFixVersion("img-b", "CVE-SHARED-1", "pkg:npm/shared-lib@1.0.0"))
	assert.Nil(t, getFixVersion("img-a", "CVE-OTHER-1", "pkg:npm/other-lib@1.0.0"), "unrelated pair must be untouched")

	n, err = db.BulkClearFixVersions(ctx, sql.BulkClearFixVersionsParams{
		CveIds:   []string{"CVE-SHARED-1"},
		Packages: []string{"pkg:npm/shared-lib@1.0.0"},
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "clear must touch both rows sharing the pair")

	assert.Nil(t, getFixVersion("img-a", "CVE-SHARED-1", "pkg:npm/shared-lib@1.0.0"))
	assert.Nil(t, getFixVersion("img-b", "CVE-SHARED-1", "pkg:npm/shared-lib@1.0.0"))
}
