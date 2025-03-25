package api

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/manager"
	"net"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/api/auth"
	"github.com/nais/v13s/internal/api/grpcmgmt"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/sources/dependencytrack"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

type Config struct {
	ListenAddr                string        `envconfig:"LISTEN_ADDR" default:"0.0.0.0:50051"`
	InternalListenAddr        string        `envconfig:"INTERNAL_LISTEN_ADDR" default:"127.0.0.1:8000"`
	DependencytrackUrl        string        `envconfig:"DEPENDENCYTRACK_URL" required:"true"`
	DependencytrackTeam       string        `envconfig:"DEPENDENCYTRACK_TEAM" default:"Administrators"`
	DependencytrackUsername   string        `envconfig:"DEPENDENCYTRACK_USERNAME" required:"true"`
	DependencytrackPassword   string        `envconfig:"DEPENDENCYTRACK_PASSWORD" required:"true"`
	DatabaseUrl               string        `envconfig:"DATABASE_URL" required:"true"`
	UpdateInterval            time.Duration `envconfig:"UPDATE_INTERVAL" default:"1m"`
	RequiredAudience          string        `envconfig:"REQUIRED_AUDIENCE" default:"vulnz"`
	AuthorizedServiceAccounts []string      `envconfig:"AUTHORIZED_SERVICE_ACCOUNTS" required:"true"`
	LogFormat                 string        `envconfig:"LOG_FORMAT" default:"json"`
	LogLevel                  string        `envconfig:"LOG_LEVEL" default:"info"`
}

func Run(ctx context.Context, c Config, log logrus.FieldLogger) error {
	ctx, signalStop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer signalStop()

	_, promReg, err := metrics.NewMeterProvider(ctx)
	if err != nil {
		return fmt.Errorf("create metric meter: %w", err)
	}
	log.Info("Initializing database")

	pool, err := database.New(ctx, c.DatabaseUrl, log.WithField("subsystem", "database"))
	if err != nil {
		log.Fatalf("Failed to create database pool: %v", err)
	}
	defer pool.Close()

	dpClient, err := dependencytrack.NewClient(
		c.DependencytrackUrl,
		c.DependencytrackTeam,
		c.DependencytrackUsername,
		c.DependencytrackPassword,
		log.WithField("subsystem", "dp-client"),
	)
	if err != nil {
		log.Fatalf("Failed to create DependencyTrack client: %v", err)
	}

	clusterConfig, err := config.CreateClusterConfigMap(
		"nav",
		[]string{"dev"},
		[]config.StaticCluster{},
	)
	if err != nil {
		log.Fatalf("Failed to create cluster config map: %v", err)
	}

	watcherMgr, err := kubernetes.NewManager(clusterConfig, log)
	if err != nil {
		log.Fatalf("Failed to create watcher manager: %v", err)
	}

	source := sources.NewDependencytrackSource(dpClient, log.WithField("subsystem", "dependencytrack"))
	ctx = manager.NewContext(ctx, sql.New(pool), source, log.WithField("subsystem", "manager"))
	_ = kubernetes.NewWorkloadWatcher(ctx, watcherMgr, log.WithField("subsystem", "workload_watcher"))

	u := updater.NewUpdater(
		pool,
		source,
		c.UpdateInterval,
		log.WithField("subsystem", "updater"),
	)
	u.Run(ctx)

	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error {
		if err = runGrpcServer(ctx, c, pool, u, log); err != nil {
			log.WithError(err).Errorf("error in GRPC server")
			return err
		}
		return nil
	})

	wg.Go(func() error {
		return runInternalHTTPServer(
			ctx,
			c.InternalListenAddr,
			promReg,
			log,
		)
	})

	<-ctx.Done()
	signalStop()
	log.Infof("shutting down...")

	ch := make(chan error)
	go func() {
		ch <- wg.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		log.Warn("timed out waiting for graceful shutdown")
	case err := <-ch:
		return err
	}

	return nil
}

func runGrpcServer(ctx context.Context, cfg Config, pool *pgxpool.Pool, u *updater.Updater, log logrus.FieldLogger) error {
	log.Info("GRPC serving on ", cfg.ListenAddr)
	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	opts := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
	}
	if !strings.HasPrefix(cfg.ListenAddr, "localhost") {
		opts = append(opts, grpc.UnaryInterceptor(auth.TokenInterceptor(cfg.RequiredAudience, cfg.AuthorizedServiceAccounts, log.WithField("subsystem", "auth"))))
	}

	s := grpc.NewServer(opts...)
	vulnerabilities.RegisterVulnerabilitiesServer(s, grpcvulnerabilities.NewServer(pool, log.WithField("subsystem", "vulnerabilities")))
	management.RegisterManagementServer(s, grpcmgmt.NewServer(ctx, pool, u, log.WithField("subsystem", "management")))

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.Serve(lis) })
	g.Go(func() error {
		<-ctx.Done()

		ch := make(chan struct{})
		go func() {
			s.GracefulStop()
			close(ch)
		}()

		select {
		case <-ch:
			// ok
		case <-time.After(5 * time.Second):
			// force shutdown
			s.Stop()
		}

		return nil
	})

	return g.Wait()
}
