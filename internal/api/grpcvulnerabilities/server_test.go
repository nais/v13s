// /go:build integration_test
package grpcvulnerabilities_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/sources/dependencytrack"
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
	ctx, db, client, _, cleanup := setupTest(t, cfg, true)
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

	ctx, _, client, _, cleanup := setupTest(t, cfg, true)
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

	ctx, _, client, _, cleanup := setupTest(t, cfg, true)
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

// TODO: create proper test, this is for manual verification
func TestServer_SuppressVulnerability(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"dev"},
		namespaces:            []string{"nais"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}

	ctx, db, client, source, cleanup := setupTest(t, cfg, false)
	defer cleanup()

	err := db.CreateImage(ctx, sql.CreateImageParams{
		Name:     "yolo",
		Tag:      "bolo",
		Metadata: map[string]string{},
	})
	assert.NoError(t, err)
	_, err = db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
		Name:         "yolo",
		WorkloadType: "app",
		Namespace:    "nais",
		Cluster:      "dev",
		ImageName:    "yolo",
		ImageTag:     "bolo",
	})
	assert.NoError(t, err)

	vulns, err := source.GetVulnerabilities(ctx, "yolo", "bolo", true)
	assert.NoError(t, err)

	params := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	cves := make([]sql.BatchUpsertCveParams, 0)
	for _, v := range vulns {
		if v.Cve.Id == "CVE-2019-16746" {
			fmt.Printf("YOlolo: %s\n", v.Cve.Id)
		}
		params = append(params, sql.BatchUpsertVulnerabilitiesParams{
			ImageName:     "yolo",
			ImageTag:      "bolo",
			Package:       v.Package,
			CveID:         v.Cve.Id,
			Source:        "dependencytrack",
			LatestVersion: v.LatestVersion,
		})
		cves = append(cves, sql.BatchUpsertCveParams{
			CveID:    v.Cve.Id,
			CveTitle: v.Cve.Title,
			CveDesc:  v.Cve.Description,
			CveLink:  v.Cve.Link,
			Severity: v.Cve.Severity.ToInt32(),
			Refs:     v.Cve.References,
		})
	}

	db.BatchUpsertCve(ctx, cves).Exec(func(i int, err error) {
		if err != nil {
			assert.NoError(t, err)
		}
	})
	db.BatchUpsertVulnerabilities(ctx, params).Exec(func(i int, err error) {
		if err != nil {
			assert.NoError(t, err)
		}
	})
	time.Sleep(1 * time.Second) // wait for the db to update

	// get vulnerabilities for workload-1
	vulnz, err := client.ListVulnerabilitiesForImage(
		ctx,
		"yolo", "bolo",
		vulnerabilities.Limit(1000),
		vulnerabilities.IncludeSuppressed(),
	)
	assert.NoError(t, err)
	//assert.Len(t, vulnz.Nodes, )

	assert.Greater(t, len(vulnz.Nodes), 1, "Expected at least one vulnerability for the image")

	var vulnToSuppress *vulnerabilities.Vulnerability
	for _, v := range vulnz.Nodes {
		if v.GetCve().GetId() == "CVE-2018-10876" {
			vulnToSuppress = v
			break
		}
	}
	assert.NotNil(t, vulnToSuppress)
	fmt.Printf(
		"Vulnerability to suppress: %s, cve: %s, severity %s, package %s\n",
		vulnToSuppress.GetId(),
		vulnToSuppress.GetCve().GetId(),
		vulnToSuppress.GetCve().GetSeverity(),
		vulnToSuppress.GetPackage(),
	)

	// set suppressed vulnerabilities for workload-1
	err = client.SuppressVulnerability(
		ctx,
		vulnToSuppress.GetId(),
		"not affected",
		"test-user",
		vulnerabilities.SuppressState_FALSE_POSITIVE,
		true)
	assert.NoError(t, err)
	/*
		t.Run("list all suppressed vulnerabilities for every cluster", func(t *testing.T) {
			resp, err := client.ListSuppressedVulnerabilities(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 1, len(resp.Nodes))
			assert.Equal(t, true, resp.Nodes[0].GetSuppress())
			assert.Equal(t, "not affected", resp.Nodes[0].GetReason())
			assert.Equal(t, "test-user", resp.Nodes[0].GetSuppressedBy())
		})

		t.Run("Get suppressed vulnerabilities for a specific image", func(t *testing.T) {
			resp, err := client.GetVulnerabilityById(ctx, vulns.Nodes[0].GetId())
			assert.NoError(t, err)
			assert.Equal(t, true, resp.GetVulnerability().GetSuppression().Suppressed)
		})*/
}
func TestServer_ListSuppressedVulnerabilities(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 1,
		vulnsPerWorkload:      1,
	}

	ctx, _, client, _, cleanup := setupTest(t, cfg, true)
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

	t.Run("Get suppressed vulnerabilities for a specific image", func(t *testing.T) {
		resp, err := client.GetVulnerabilityById(ctx, vulns.Nodes[0].GetId())
		assert.NoError(t, err)
		assert.Equal(t, true, resp.GetVulnerability().GetSuppression().Suppressed)
	})
}

func TestServer_GetVulnerabilitySummary(t *testing.T) {
	cfg := testSetupConfig{
		clusters:              []string{"cluster-1"},
		namespaces:            []string{"namespace-1"},
		workloadsPerNamespace: 4,
		vulnsPerWorkload:      4,
	}

	ctx, _, client, _, cleanup := setupTest(t, cfg, true)
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

	ctx, _, client, _, cleanup := setupTest(t, cfg, true)
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

	ctx, db, client, _, cleanup := setupTest(t, cfg, true)
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

func setupTest(t *testing.T, cfg testSetupConfig, testContainers bool) (context.Context, *sql.Queries, vulnerabilities.Client, sources.Source, func()) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, testContainers)
	db := sql.New(pool)

	// TODO: make configurable with testcontainers
	dpClient, err := dependencytrack.NewClient(
		"http://localhost:9010/api",
		"Administrators",
		"admin",
		"yolo",
		logrus.WithField("subsystem", "dp-client"),
	)
	if err != nil {
		log.Fatalf("Failed to create DependencyTrack client: %v", err)
	}

	source := sources.NewDependencytrackSource(dpClient, logrus.WithField("subsystem", "dependencytrack"))

	_, client, cleanup := startGrpcServer(pool, source)

	err = db.ResetDatabase(ctx)
	assert.NoError(t, err)

	workloads := generateTestWorkloads(cfg.clusters, cfg.namespaces, cfg.workloadsPerNamespace, cfg.vulnsPerWorkload)

	err = seedDb(t, db, workloads)
	assert.NoError(t, err)

	return ctx, db, client, source, func() {
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
func startGrpcServer(db *pgxpool.Pool, source sources.Source) (*grpc.Server, vulnerabilities.Client, func()) {
	lis := bufconn.Listen(1024 * 1024)
	server := grpcvulnerabilities.NewServer(db, source, logrus.NewEntry(logrus.StandardLogger()))
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
