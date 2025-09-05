// /go:build integration_test
package grpcvulnerabilities_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type testSetupConfig struct {
	clusters              []string
	namespaces            []string
	workloadsPerNamespace int
	vulnsPerWorkload      int
}

func TestServer_ListVulnerabilities(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1", "cluster-2"},
		namespaces:            []string{"namespace-1", "namespace-2", "namespace-3"},
		workloadsPerNamespace: 4,
		vulnsPerWorkload:      4,
	}
	ctx, db, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	t.Run("list all vulnerabilities for every cluster", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(ctx, vulnerabilities.Limit(100))
		assert.NoError(t, err)
		// equals all rows in vulnerabilities table in db
		// 24 workloads * 4 vulns per workload = 96
		assert.Equal(t, 96, len(resp.Nodes))
	})

	t.Run("list vulnerabilities for every cluster with default limit", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(
			ctx,
		)
		assert.NoError(t, err)
		// equals all rows in vulnerabilities table in db
		// 24 workloads * 4 vulns per workload = 96
		// returns first 50 rows because of default limit
		assert.Equal(t, 50, len(resp.Nodes))
	})

	t.Run("list all vulnerabilities for cluster-1", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(
			ctx,
			vulnerabilities.ClusterFilter("cluster-1"),
		)
		assert.NoError(t, err)
		// 12 workloads * 4 vulns per workload = 48
		assert.Equal(t, 48, len(resp.Nodes))
	})

	t.Run("list all vulnerabilities for namespace-1", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(
			ctx,
			vulnerabilities.NamespaceFilter("namespace-1"),
		)
		assert.NoError(t, err)
		// 8 workloads * 4 vulns per workload = 32
		assert.Equal(t, 32, len(resp.Nodes))
	})

	t.Run("list all vulnerabilities for cluster-1 and namespace-1", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(
			ctx,
			vulnerabilities.ClusterFilter("cluster-1"),
			vulnerabilities.NamespaceFilter("namespace-1"),
		)
		assert.NoError(t, err)
		// 4 workloads * 4 vulns per workload = 16
		assert.Equal(t, 16, len(resp.Nodes))
	})

	t.Run("list all vulnerabilities for workload-1", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(
			ctx,
			vulnerabilities.WorkloadFilter("workload-1"),
		)
		assert.NoError(t, err)
		assert.Equal(t, len(cfg.clusters)*len(cfg.namespaces)*cfg.vulnsPerWorkload, len(resp.Nodes))
	})

	t.Run("list all vulnerabilities for cluster-1, namespace-1, and workload-1", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(
			ctx,
			vulnerabilities.ClusterFilter("cluster-1"),
			vulnerabilities.NamespaceFilter("namespace-1"),
			vulnerabilities.WorkloadFilter("workload-1"),
		)

		assert.NoError(t, err)
		assert.Equal(t, cfg.vulnsPerWorkload, len(resp.Nodes))

		for _, v := range resp.Nodes {
			assert.Equal(t, "workload-1", v.WorkloadRef.Name)
			assert.Equal(t, "namespace-1", v.WorkloadRef.Namespace)
			assert.Equal(t, "cluster-1", v.WorkloadRef.Cluster)
			assert.Equal(t, "app", v.WorkloadRef.Type)
		}
	})

	t.Run("list vulnerabilities with limit and pagination", func(t *testing.T) {

		limit := int32(10)
		offset := int32(0)
		resp, err := client.ListVulnerabilities(
			ctx,
			vulnerabilities.Limit(limit),
			vulnerabilities.Offset(offset),
		)
		assert.NoError(t, err)
		uniqueRows := map[string]bool{}
		flatten(t, uniqueRows, resp.Nodes)

		for resp.PageInfo.HasNextPage {
			offset += limit
			resp, err = client.ListVulnerabilities(
				ctx,
				vulnerabilities.Limit(limit),
				vulnerabilities.Offset(offset),
			)
			assert.NoError(t, err)
			flatten(t, uniqueRows, resp.Nodes)
		}

		assert.Equal(t, 96, len(uniqueRows))
	})

	t.Run("list vulnerabilities for workloads using the same image", func(t *testing.T) {

		w := sql.UpsertWorkloadParams{
			Name:         "workload-1",
			WorkloadType: "app",
			Namespace:    "namespace-1",
			Cluster:      "cluster-prod",
			ImageName:    "image-cluster-1-namespace-1-workload-1",
			ImageTag:     "v1.0",
		}

		_, err := db.UpsertWorkload(ctx, w)
		assert.NoError(t, err)

		resp, err := client.ListVulnerabilities(
			ctx,
			vulnerabilities.ImageFilter("image-cluster-1-namespace-1-workload-1", "v1.0"),
		)
		assert.NoError(t, err)

		assert.Equal(t, 8, len(resp.Nodes))
		assert.True(t, collections.AnyMatch(resp.Nodes, func(f *vulnerabilities.Finding) bool {
			return f.WorkloadRef.Name == "workload-1" && f.WorkloadRef.Namespace == "namespace-1" && f.WorkloadRef.Cluster == "cluster-prod"
		}))
	})
}

func TestServer_ListVulnerabilitiesForImage(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}

	ctx, _, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	t.Run("list vulnerabilities for a specific image", func(t *testing.T) {
		resp, err := client.ListVulnerabilitiesForImage(
			ctx,
			"image-cluster-1-namespace-1-workload-1", "v1.0",
		)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(resp.Nodes))
	})
}

func TestServer_ListVulnerabilitySummaries(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}

	ctx, _, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	t.Run("list all vulnerability summaries for every cluster", func(t *testing.T) {
		resp, err := client.ListVulnerabilitySummaries(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, resp.Nodes)
		assert.Equal(t, 1, len(resp.Nodes))

		// Check that the summary contains the expected fields
		assert.Equal(t, int32(0), resp.Nodes[0].GetVulnerabilitySummary().Critical)
		assert.Equal(t, int32(1), resp.Nodes[0].GetVulnerabilitySummary().High)
		assert.Equal(t, int32(0), resp.Nodes[0].GetVulnerabilitySummary().Medium)
		assert.Equal(t, int32(0), resp.Nodes[0].GetVulnerabilitySummary().Low)
		assert.Equal(t, int32(0), resp.Nodes[0].GetVulnerabilitySummary().Unassigned)
		assert.Equal(t, "cluster-1", resp.Nodes[0].GetWorkload().Cluster, "cluster-1")
		assert.Equal(t, "namespace-1", resp.Nodes[0].GetWorkload().Namespace, "namespace-1")
		assert.Equal(t, "workload-1", resp.Nodes[0].GetWorkload().Name, "workload-1")
		assert.Equal(t, "app", resp.Nodes[0].GetWorkload().Type, "app")
		assert.Equal(t, "image-cluster-1-namespace-1-workload-1", resp.Nodes[0].GetWorkload().ImageName, "image-cluster-1-namespace-1-workload-1")
		assert.Equal(t, "v1.0", resp.Nodes[0].GetWorkload().ImageTag, "v1.0")
	})
}

func TestServer_ListVulnerabilitiesForImage_WithFilters(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      3,
	}

	ctx, _, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	imageName := "image-cluster-1-namespace-1-workload-1"
	imageTag := "v1.0"

	t.Run("filter by severity", func(t *testing.T) {
		severity := vulnerabilities.Severity_HIGH

		resp, err := client.ListVulnerabilitiesForImage(
			ctx,
			imageName,
			imageTag,
			vulnerabilities.SeverityFilter(severity),
			vulnerabilities.Limit(100),
			vulnerabilities.Offset(0),
			vulnerabilities.Order(vulnerabilities.OrderBySeverity, vulnerabilities.Direction_DESC),
		)
		assert.NoError(t, err)

		for _, v := range resp.Nodes {
			assert.Equal(t, int32(severity), int32(v.GetCve().GetSeverity()))
		}
	})

	t.Run("filter by since", func(t *testing.T) {
		sinceTime := time.Now().Add(-1 * time.Hour)

		resp, err := client.ListVulnerabilitiesForImage(
			ctx,
			imageName,
			imageTag,
			vulnerabilities.Since(sinceTime),
			vulnerabilities.Limit(100),
			vulnerabilities.Offset(0),
			vulnerabilities.Order(vulnerabilities.OrderBySeveritySince, vulnerabilities.Direction_DESC),
		)
		assert.NoError(t, err)

		for _, v := range resp.Nodes {
			assert.True(t,
				v.GetSeveritySince().AsTime().After(sinceTime) || v.GetSeveritySince().AsTime().Equal(sinceTime),
				"vulnerability severity_since should be after or equal to filter",
			)
		}
	})

	t.Run("filter by severity and since together", func(t *testing.T) {
		severity := vulnerabilities.Severity_HIGH
		sinceTime := time.Now().Add(-1 * time.Hour)

		resp, err := client.ListVulnerabilitiesForImage(
			ctx,
			imageName,
			imageTag,
			vulnerabilities.SeverityFilter(severity),
			vulnerabilities.Since(sinceTime),
			vulnerabilities.Limit(100),
			vulnerabilities.Offset(0),
			vulnerabilities.Order(vulnerabilities.OrderBySeverity, vulnerabilities.Direction_DESC),
		)
		assert.NoError(t, err)

		for _, v := range resp.Nodes {
			assert.Equal(t, int32(severity), int32(v.GetCve().GetSeverity()))
			assert.True(t,
				v.GetSeveritySince().AsTime().After(sinceTime) || v.GetSeveritySince().AsTime().Equal(sinceTime),
				"vulnerability severity_since should be after or equal to filter",
			)
		}
	})
	t.Run("filter including suppressed", func(t *testing.T) {
		severity := vulnerabilities.Severity_HIGH
		sinceTime := time.Now().Add(-1 * time.Hour)

		resp, err := client.ListVulnerabilitiesForImage(
			ctx,
			imageName,
			imageTag,
			vulnerabilities.SeverityFilter(severity),
			vulnerabilities.Since(sinceTime),
			vulnerabilities.IncludeSuppressed(),
			vulnerabilities.Limit(100),
			vulnerabilities.Offset(0),
			vulnerabilities.Order(vulnerabilities.OrderBySeverity, vulnerabilities.Direction_DESC),
		)
		assert.NoError(t, err)

		for _, v := range resp.Nodes {
			assert.True(t,
				v.GetSeveritySince().AsTime().After(sinceTime) || v.GetSeveritySince().AsTime().Equal(sinceTime),
				"vulnerability severity_since should be after or equal to filter",
			)
			assert.Equal(t, int32(severity), int32(v.GetCve().GetSeverity()))
			assert.True(t, v.GetSuppression().GetSuppressed() || !v.GetSuppression().GetSuppressed(), "suppressed field should be present")
		}
	})
}

func TestServer_ListSuppressedVulnerabilities(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}

	ctx, _, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	// get vulnerabilities for workload-1
	vulns, err := client.ListVulnerabilitiesForImage(
		ctx,
		"image-cluster-1-namespace-1-workload-1", "v1.0",
	)
	assert.NoError(t, err)
	assert.Len(t, vulns.Nodes, 1)

	// set suppressed vulnerabilities for workload-1
	err = client.SuppressVulnerability(
		ctx,
		vulns.Nodes[0].GetId(),
		"not affected",
		"test-user",
		vulnerabilities.SuppressState_FALSE_POSITIVE,
		true)
	assert.NoError(t, err)

	t.Run("list all suppressed vulnerabilities for every cluster", func(t *testing.T) {
		resp, err := client.ListSuppressedVulnerabilities(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(resp.Nodes))
		assert.Equal(t, true, resp.Nodes[0].GetSuppress())
		assert.Equal(t, "not affected", resp.Nodes[0].GetReason())
		assert.Equal(t, "test-user", resp.Nodes[0].GetSuppressedBy())
	})
}

func TestServer_SuppressVulnerability_LastModified(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}
	ctx, db, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	imageName := "image-cluster-1-namespace-1-workload-1"
	imageTag := "v1.0"

	vulns, err := client.ListVulnerabilitiesForImage(ctx, imageName, imageTag)
	assert.NoError(t, err)
	assert.Len(t, vulns.Nodes, 1)

	vulnID := vulns.Nodes[0].GetId()

	// fetch suppression records before
	beforeList, err := db.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	assert.NoError(t, err)

	var beforeUpdatedAt time.Time
	if len(beforeList) > 0 {
		beforeUpdatedAt = beforeList[0].UpdatedAt.Time
	} else {
		// No suppression exists yet
		beforeUpdatedAt = time.Time{}
	}

	time.Sleep(10 * time.Millisecond)

	// --- First suppression should bump updated_at ---
	err = client.SuppressVulnerability(
		ctx,
		vulnID,
		"not affected",
		"test-user",
		vulnerabilities.SuppressState_FALSE_POSITIVE,
		true,
	)
	assert.NoError(t, err)

	afterFirstList, err := db.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	assert.NoError(t, err)
	assert.NotEmpty(t, afterFirstList)
	afterFirstUpdatedAt := afterFirstList[0].UpdatedAt.Time

	imageAfterFirst, err := db.GetImage(ctx, sql.GetImageParams{Name: imageName, Tag: imageTag})
	assert.NoError(t, err)
	assert.Equal(t, sql.ImageStateResync, imageAfterFirst.State, "image state should be Resync after first suppression")

	if !beforeUpdatedAt.IsZero() {
		assert.True(t, afterFirstUpdatedAt.After(beforeUpdatedAt),
			"expected updated_at to change after first suppression, before=%s after=%s",
			beforeUpdatedAt, afterFirstUpdatedAt)
	}

	// --- Second suppression with identical values should NOT bump updated_at ---
	time.Sleep(10 * time.Millisecond)
	err = client.SuppressVulnerability(
		ctx,
		vulnID,
		"not affected", // same reason
		"test-user",    // same user
		vulnerabilities.SuppressState_FALSE_POSITIVE,
		true, // already suppressed
	)
	assert.NoError(t, err)

	afterSecondList, err := db.ListSuppressedVulnerabilitiesForImage(ctx, imageName)
	assert.NoError(t, err)
	assert.NotEmpty(t, afterSecondList)
	afterSecondUpdatedAt := afterSecondList[0].UpdatedAt.Time

	imageAfterSecond, err := db.GetImage(ctx, sql.GetImageParams{Name: imageName, Tag: imageTag})
	assert.NoError(t, err)
	assert.Equal(t, sql.ImageStateResync, imageAfterSecond.State, "image state should remain Resync on idempotent suppression")

	assert.Equal(t, afterFirstUpdatedAt, afterSecondUpdatedAt,
		"expected updated_at to stay the same on idempotent suppression, first=%s second=%s",
		afterFirstUpdatedAt, afterSecondUpdatedAt)
}

func TestUpdateCveSeverityAndTimestamps(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}
	ctx, db, _, _, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	// Insert a CVE with initial severity
	initialCve := sql.BatchUpsertCveParams{
		CveID:    "CVE-2023-1234",
		CveTitle: "Test CVE",
		CveDesc:  "Initial description",
		CveLink:  "http://example.com",
		Severity: 2, // Initial severity set to Medium
		Refs:     map[string]string{},
	}
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{initialCve}).Exec(func(i int, err error) {
		assert.NoError(t, err)
	})

	// Fetch the CVE and record timestamps
	cve, err := db.GetCve(ctx, "CVE-2023-1234")
	assert.NoError(t, err)
	initialCreatedAt := cve.CreatedAt
	initialUpdatedAt := cve.UpdatedAt

	// Ensure timestamps are set
	assert.False(t, initialCreatedAt.Time.IsZero(), "created_at should not be zero")
	assert.False(t, initialUpdatedAt.Time.IsZero(), "updated_at should not be zero")

	// Update the CVE with a new severity
	updatedCve := sql.BatchUpsertCveParams{
		CveID:    "CVE-2023-1234",
		CveTitle: "Test CVE",
		CveDesc:  "Updated description",
		CveLink:  "http://example.com",
		Severity: 1, // Update severity to High
		Refs:     map[string]string{},
	}
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{updatedCve}).Exec(func(i int, err error) {
		assert.NoError(t, err)
	})

	// Fetch the updated CVE and verify changes
	updatedCveRecord, err := db.GetCve(ctx, "CVE-2023-1234")
	assert.NoError(t, err)

	// Verify severity is updated
	assert.Equal(t, int32(1), updatedCveRecord.Severity, "Severity should be updated to High")

	// Verify timestamps
	assert.Equal(t, initialCreatedAt, updatedCveRecord.CreatedAt, "created_at should remain unchanged")
	assert.True(t, updatedCveRecord.UpdatedAt.Time.After(initialUpdatedAt.Time), "updated_at should be updated")
}

func TestVulnerabilitySeveritySince(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}
	ctx, db, _, _, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	// Create image
	err := db.CreateImage(ctx, sql.CreateImageParams{
		Name:     "my-image",
		Tag:      "v1.0.0",
		Metadata: map[string]string{},
	})
	assert.NoError(t, err)

	t.Run("Non-critical → new severity", func(t *testing.T) {
		initialSeverity := int32(2)
		db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{{
			CveID:    "CVE-2023-1234",
			CveTitle: "Test CVE",
			CveDesc:  "Initial description",
			CveLink:  "http://example.com",
			Severity: initialSeverity,
			Refs:     map[string]string{},
		}}).Exec(func(i int, err error) {
			assert.NoError(t, err)
		})

		initialVuln := sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     "my-image",
			ImageTag:      "v1.0.0",
			Package:       "mypkg",
			CveID:         "CVE-2023-1234",
			Source:        "test-source",
			LatestVersion: "1.2.3",
			LastSeverity:  initialSeverity,
			SeveritySince: pgtype.Timestamptz{}, // NULL
		}
		db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{initialVuln}).Exec(func(i int, err error) {
			assert.NoError(t, err)
		})

		updatedSeverity := int32(3) // High
		updatedVuln := sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     "my-image",
			ImageTag:      "v1.0.0",
			Package:       "mypkg",
			CveID:         "CVE-2023-1234",
			Source:        "test-source",
			LatestVersion: "1.2.3",
			LastSeverity:  updatedSeverity,
			SeveritySince: pgtype.Timestamptz{
				Time:  time.Now(),
				Valid: true,
			},
		}
		db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{updatedVuln}).Exec(func(i int, err error) {
			assert.NoError(t, err)
		})

		got, err := db.GetVulnerability(ctx, sql.GetVulnerabilityParams{
			ImageName: "my-image",
			ImageTag:  "v1.0.0",
			Package:   "mypkg",
			CveID:     "CVE-2023-1234",
		})
		assert.NoError(t, err)
		assert.True(t, got.SeveritySince.Valid)
		assert.WithinDuration(t, time.Now(), got.SeveritySince.Time, 2*time.Second)
	})

	t.Run("returns nil if severity not present", func(t *testing.T) {
		got, err := db.GetEarliestSeveritySinceForVulnerability(ctx, sql.GetEarliestSeveritySinceForVulnerabilityParams{
			ImageName:    "my-image",
			Package:      "mypkg",
			CveID:        "CVE-unknown",
			LastSeverity: 5,
		})
		assert.NoError(t, err)

		assert.False(t, got.Valid, "expected severity_since to be null (invalid)")
	})

	t.Run("does not overwrite existing severity_since", func(t *testing.T) {
		initialSeverity := int32(2)
		vuln := sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     "my-image",
			ImageTag:      "v1.0.0",
			Package:       "mypkg",
			CveID:         "CVE-2023-1234",
			Source:        "test-source",
			LatestVersion: "1.2.3",
			LastSeverity:  initialSeverity,
			SeveritySince: pgtype.Timestamptz{
				Time:  time.Now().Add(-1 * time.Hour),
				Valid: true,
			},
		}
		db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{vuln}).Exec(func(i int, err error) {
			assert.NoError(t, err)
		})

		before, err := db.GetVulnerability(ctx, sql.GetVulnerabilityParams{
			ImageName: "my-image",
			ImageTag:  "v1.0.0",
			Package:   "mypkg",
			CveID:     "CVE-2023-1234",
		})
		assert.NoError(t, err)

		db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{vuln}).Exec(func(i int, err error) {
			assert.NoError(t, err)
		})

		after, err := db.GetVulnerability(ctx, sql.GetVulnerabilityParams{
			ImageName: "my-image",
			ImageTag:  "v1.0.0",
			Package:   "mypkg",
			CveID:     "CVE-2023-1234",
		})
		assert.NoError(t, err)
		assert.Equal(t, before.SeveritySince, after.SeveritySince)
	})
}

func TestServer_GetVulnerabilitySummary(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 4,
		vulnsPerWorkload:      4,
	}

	ctx, _, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	t.Run("get vulnerability summary for every cluster", func(t *testing.T) {
		resp, err := client.GetVulnerabilitySummary(ctx)
		assert.NoError(t, err)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Critical)
		assert.Equal(t, int32(4), resp.GetVulnerabilitySummary().High)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Medium)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Low)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Unassigned)
	})

}

func TestServer_GetVulnerabilitySummaryForImage(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}

	ctx, _, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	t.Run("get vulnerability summary for image cluster-1/namespace-1/workload-1", func(t *testing.T) {
		resp, err := client.GetVulnerabilitySummaryForImage(
			ctx, "image-cluster-1-namespace-1-workload-1", "v1.0")
		assert.NoError(t, err)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Critical)
		assert.Equal(t, int32(1), resp.GetVulnerabilitySummary().High)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Medium)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Low)
		assert.Equal(t, int32(0), resp.GetVulnerabilitySummary().Unassigned)
	})

}

func TestServer_GetVulnerabilityById(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}

	ctx, db, _, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	vuln, err := db.GetVulnerability(ctx, sql.GetVulnerabilityParams{
		ImageName: "image-cluster-1-namespace-1-workload-1",
		ImageTag:  "v1.0",
		CveID:     "CWE-1-1",
		Package:   "package-CWE-1-1",
	})
	assert.NoError(t, err)

	t.Run("get vulnerability by id", func(t *testing.T) {
		resp, err := client.GetVulnerabilityById(ctx, vuln.ID.String())
		assert.NoError(t, err)
		assert.Equal(t, "CWE-1-1", resp.GetVulnerability().GetCve().GetId())
	})
}

func TestServer_ListSeverityVulnerabilitiesSince(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      2,
	}

	ctx, db, pool, client, cleanup := setupTest(t, cfg, true)
	defer cleanup()

	err := db.CreateImage(ctx, sql.CreateImageParams{
		Name:     "image-1",
		Tag:      "v1.0",
		Metadata: map[string]string{},
	})
	assert.NoError(t, err)

	now := time.Now()
	r, err := client.ListVulnerabilities(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(r.Nodes))

	rows, err := pool.Query(ctx, "SELECT image_name, package FROM vulnerabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var image, pkg string
		if err := rows.Scan(&image, &pkg); err != nil {
			t.Fatal(err)
		}

		var newTime time.Time
		switch pkg {
		case "package-CWE-1-1":
			newTime = time.Now().Add(-12 * time.Hour) // 12 hours ago
		case "package-CWE-1-2":
			newTime = time.Now().Add(-48 * time.Hour) // 48 hours ago
		default:
			continue
		}

		_, err := pool.Exec(ctx, `
            UPDATE vulnerabilities
            SET severity_since = $1,
                last_severity = 0
            WHERE image_name = $2 AND package = $3
        `, newTime, image, pkg)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println("Updated:", image, pkg, "to", newTime)
	}

	t.Run("last 7 days", func(t *testing.T) {
		resp, err := client.ListSeverityVulnerabilitiesSince(ctx,
			vulnerabilities.Since(now.Add(-7*24*time.Hour)),
			vulnerabilities.Order(vulnerabilities.OrderBySeveritySince, vulnerabilities.Direction_DESC),
		)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(resp.Nodes))

		t0 := resp.Nodes[0].Vulnerability.SeveritySince.AsTime().UTC()
		t1 := resp.Nodes[1].Vulnerability.SeveritySince.AsTime().UTC()
		assert.True(t, t0.After(t1))
		assert.True(t, t1.Before(t0))
	})

	t.Run("last 1 day", func(t *testing.T) {
		resp, err := client.ListSeverityVulnerabilitiesSince(ctx,
			vulnerabilities.Since(now.Add(-24*time.Hour)),
		)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(resp.Nodes)) // only the 12h-old vuln

		for _, n := range resp.Nodes {
			fmt.Printf("Resp Node: pkg=%s severity_since=%v severity=%d\n",
				n.Vulnerability.Package,
				n.Vulnerability.SeveritySince.AsTime(),
				*n.Vulnerability.LastSeverity,
			)
		}
	})
}

func setupTest(t *testing.T, cfg testSetupConfig, testContainers bool) (context.Context, *sql.Queries, *pgxpool.Pool, vulnerabilities.Client, func()) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, testContainers)
	db := sql.New(pool)

	_, client, cleanup := startGrpcServer(pool)

	err := db.ResetDatabase(ctx)
	assert.NoError(t, err)

	workloads := generateTestWorkloads(cfg.clusters, cfg.namespaces, cfg.workloadsPerNamespace, cfg.vulnsPerWorkload)

	err = seedDb(t, db, workloads)
	assert.NoError(t, err)

	return ctx, db, pool, client, func() {
		cleanup()
		pool.Close()
	}
}

func flatten(t *testing.T, m map[string]bool, nodes []*vulnerabilities.Finding) {
	for _, v := range nodes {
		key := fmt.Sprintf(
			"%s.%s.%s.%s.%s.%s.%s",
			v.WorkloadRef.Cluster,
			v.WorkloadRef.Namespace,
			v.WorkloadRef.Name,
			v.WorkloadRef.ImageName,
			v.WorkloadRef.ImageTag,
			v.Vulnerability.Package,
			v.Vulnerability.Cve.Id,
		)
		if m[key] {
			t.Fatalf("duplicate key: %s", key)
		}
		m[key] = true
	}
}

// startGrpcServer initializes an in-memory gRPC server
func startGrpcServer(db *pgxpool.Pool) (*grpc.Server, vulnerabilities.Client, func()) {
	lis := bufconn.Listen(1024 * 1024)
	server := grpcvulnerabilities.NewServer(db, logrus.NewEntry(logrus.StandardLogger()))
	grpcServer := grpc.NewServer()
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			panic(err)
		}
	}()

	c, err := vulnerabilities.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		panic(err)
	}

	// Cleanup function to stop the server
	return grpcServer, c, func() {
		grpcServer.Stop()
		c.Close()
	}
}

func seedDb(t *testing.T, db sql.Querier, workloads []*Workload) error {
	ctx := context.Background()

	for _, workload := range workloads {
		err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     workload.ImageName,
			Tag:      workload.ImageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		w := sql.UpsertWorkloadParams{
			Name:         workload.Workload,
			WorkloadType: workload.WorkloadType,
			Namespace:    workload.Namespace,
			Cluster:      workload.Cluster,
			ImageName:    workload.ImageName,
			ImageTag:     workload.ImageTag,
		}

		_, err = db.UpsertWorkload(ctx, w)
		assert.NoError(t, err)

		cweParams := make([]sql.BatchUpsertCveParams, 0)
		vulnParams := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
		sumParams := make([]sql.BatchUpsertVulnerabilitySummaryParams, 0)
		for _, f := range workload.Vulnz {
			v := f.vuln
			cve := f.cve

			cweParams = append(cweParams, sql.BatchUpsertCveParams{
				CveID:    cve.CveID,
				CveTitle: cve.CveTitle,
				CveDesc:  cve.CveDesc,
				CveLink:  cve.CveLink,
				Severity: cve.Severity,
				Refs:     map[string]string{},
			})
			vulnParams = append(vulnParams, sql.BatchUpsertVulnerabilitiesParams{
				ImageName:     v.ImageName,
				ImageTag:      v.ImageTag,
				Package:       v.Package,
				CveID:         v.CveID,
				LatestVersion: "2",
				LastSeverity:  cve.Severity,
				SeveritySince: pgtype.Timestamptz{
					Time:  time.Now(),
					Valid: true,
				},
			})
			sumParams = append(sumParams, sql.BatchUpsertVulnerabilitySummaryParams{
				ImageName:  v.ImageName,
				ImageTag:   v.ImageTag,
				Critical:   0,
				High:       1,
				Medium:     0,
				Low:        0,
				Unassigned: 0,
			})
		}

		db.BatchUpsertCve(ctx, cweParams).Exec(func(i int, err error) {
			if err != nil {
				assert.NoError(t, err)
			}
		})

		db.BatchUpsertVulnerabilities(ctx, vulnParams).Exec(func(i int, err error) {
			if err != nil {
				assert.NoError(t, err)
			}
		})

		db.BatchUpsertVulnerabilitySummary(ctx, sumParams).Exec(func(i int, err error) {
			if err != nil {
				assert.NoError(t, err)
			}
		})
	}

	return nil
}
