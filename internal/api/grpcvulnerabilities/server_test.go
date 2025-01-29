// /go:build integration_test
package grpcvulnerabilities_test

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"testing"
)

func TestServer_ListVulnerabilities(t *testing.T) {
	ctx := context.Background()

	pool := getPool(ctx, t, false)
	defer pool.Close()
	db := sql.New(pool)

	_, client, cleanup := startGrpcServer(db)
	defer cleanup()

	err := db.ResetDatabase(ctx)
	assert.NoError(t, err)
	// Define clusters, namespaces, and workloads
	clusters := []string{"cluster-1", "cluster-2"}
	namespaces := []string{"namespace-1", "namespace-2", "namespace-3"}
	// should give 24 workloads in total, 12 per cluster
	workloadsPerNamespace := 4
	vulnsPerWorkload := 4
	workloads := generateTestWorkloads(clusters, namespaces, workloadsPerNamespace, vulnsPerWorkload)

	err = seedDb(t, db, workloads)
	assert.NoError(t, err)

	t.Run("list all vulnerabilities for every cluster", func(t *testing.T) {
		resp, err := client.ListVulnerabilities(ctx, vulnerabilities.Limit(100))
		assert.NoError(t, err)
		// equals all rows in vulnerabilities table in db
		// 24 workloads * 4 vulns per workload = 96
		assert.Equal(t, 96, len(resp.Vulnerabilities))
	})
}

// startGrpcServer initializes an in-memory gRPC server
func startGrpcServer(db sql.Querier) (*grpc.Server, vulnerabilities.Client, func()) {
	lis := bufconn.Listen(1024 * 1024)
	server := grpcvulnerabilities.NewServer(db)
	grpcServer := grpc.NewServer()
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Errorf("failed to serve: %v", err)
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

func getPool(ctx context.Context, t *testing.T, testcontainers bool) *pgxpool.Pool {
	log, _ := logrustest.NewNullLogger()
	if testcontainers {
		container, dsn, err := startPostgresql(ctx, log)
		if err != nil {
			t.Fatalf("failed to start postgresql: %v", err)
		}
		return getConnection(ctx, t, container, dsn, log)
	}
	pool, err := database.New(ctx, "postgres://v13s:v13s@127.0.0.1:3002/v13s?sslmode=disable", log.WithField("component", "database"))
	if err != nil {
		t.Fatalf("failed to create database pool: %v", err)
	}
	return pool
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

		err = db.UpsertWorkload(ctx, w)
		assert.NoError(t, err)

		cweParams := make([]sql.BatchUpsertCweParams, 0)
		vulnParams := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
		for _, f := range workload.Vulnz {
			v := f.vuln
			cwe := f.cwe
			cweParams = append(cweParams, sql.BatchUpsertCweParams{
				CweID:    cwe.CweID,
				CweTitle: cwe.CweTitle,
				CweDesc:  cwe.CweDesc,
				CweLink:  cwe.CweLink,
				Severity: cwe.Severity,
			})
			vulnParams = append(vulnParams, sql.BatchUpsertVulnerabilitiesParams{
				ImageName: v.ImageName,
				ImageTag:  v.ImageTag,
				Package:   v.Package,
				CweID:     v.CweID,
			})
		}

		db.BatchUpsertCwe(ctx, cweParams).Exec(func(i int, err error) {
			if err != nil {
				assert.NoError(t, err)
			}
		})

		db.BatchUpsertVulnerabilities(ctx, vulnParams).Exec(func(i int, err error) {
			if err != nil {
				assert.NoError(t, err)
			}
		})

	}

	return nil
}

func startPostgresql(ctx context.Context, log logrus.FieldLogger) (container *postgres.PostgresContainer, dsn string, err error) {
	container, err = postgres.Run(
		ctx,
		"docker.io/postgres:16-alpine",
		postgres.WithDatabase("test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		postgres.WithSQLDriver("pgx"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to start container: %w", err)
	}

	dsn, err = container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, "", fmt.Errorf("failed to get connection string: %w", err)
	}

	pool, err := database.NewPool(ctx, dsn, log, true)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create pool: %w", err)
	}
	pool.Close()

	if err := container.Snapshot(ctx); err != nil {
		return nil, "", fmt.Errorf("failed to snapshot: %w", err)
	}

	return container, dsn, nil
}

func getConnection(ctx context.Context, t *testing.T, container *postgres.PostgresContainer, dsn string, log logrus.FieldLogger) *pgxpool.Pool {
	pool, _ := database.NewPool(ctx, dsn, log, false)

	t.Cleanup(func() {
		pool.Close()
		if err := container.Restore(ctx); err != nil {
			t.Fatalf("failed to restore database: %v", err)
		}
	})

	return pool
}
