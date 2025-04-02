package api

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

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

	listener, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		log.WithError(err).Fatalf("Failed to listen on %s", c.ListenAddr)
	}

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

	source := sources.NewDependencytrackSource(dpClient, log.WithField("subsystem", "dependencytrack"))
	u := updater.NewUpdater(
		pool,
		source,
		c.UpdateInterval,
		log.WithField("subsystem", "updater"),
	)
	u.Run(ctx)

	grpcServer := createGrpcServer(ctx, c, pool, u, log)

	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error {
		if err := grpcServer.Serve(listener); err != nil {
			log.WithError(err).Errorf("Failed to serve gRPC server")
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

func createGrpcServer(parentCtx context.Context, cfg Config, pool *pgxpool.Pool, u *updater.Updater, field logrus.FieldLogger) *grpc.Server {
	serverOpts := make([]grpc.ServerOption, 0)

	if !strings.HasPrefix(cfg.ListenAddr, "localhost") {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(auth.TokenInterceptor(cfg.RequiredAudience, cfg.AuthorizedServiceAccounts, field.WithField("subsystem", "auth"))))
	}

	grpcServer := grpc.NewServer(serverOpts...)
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, grpcvulnerabilities.NewServer(pool, field.WithField("subsystem", "vulnerabilities")))
	management.RegisterManagementServer(grpcServer, grpcmgmt.NewServer(parentCtx, pool, u, field.WithField("subsystem", "management")))

	return grpcServer
}
