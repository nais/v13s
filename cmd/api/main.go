package main

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/api/auth"
	"github.com/nais/v13s/internal/api/grpcmgmt"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/logger"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nais/v13s/internal/database"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/internal/sources/dependencytrack"
	"google.golang.org/grpc"
)

const (
	exitCodeSuccess = iota
	exitCodeLoggerError
	exitCodeRunError
)

type config struct {
	ListenAddr                string        `envconfig:"LISTEN_ADDR" default:"0.0.0.0:50051"`
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

// handle env vars better
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := logrus.StandardLogger()

	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	var c config
	err = envconfig.Process("V13S", &c)
	if err != nil {
		log.WithError(err).Errorf("error when processing configuration")
	}

	appLogger := setupLogger(log, c.LogFormat, c.LogLevel)
	err = run(ctx, c, appLogger)
	if err != nil {
		appLogger.WithError(err).Errorf("error in run()")
		os.Exit(exitCodeRunError)
	}

	os.Exit(exitCodeSuccess)
}

func run(ctx context.Context, c config, log logrus.FieldLogger) error {
	listener, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		log.WithError(err).Fatalf("Failed to listen on %s", c.ListenAddr)
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

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- grpcServer.Serve(listener)
	}()

	select {
	case <-stop:
		log.Info("Shutting down gracefully")
	case err := <-srvErr:
		log.Fatalf("GRPC Server Error: %v", err)
	}

	grpcServer.GracefulStop()
	return nil
}

func setupLogger(log *logrus.Logger, logFormat, logLevel string) logrus.FieldLogger {
	appLogger, err := logger.New(logFormat, logLevel)
	if err != nil {
		log.WithError(err).Errorf("error when creating application logger")
		os.Exit(exitCodeLoggerError)
	}

	return appLogger
}

func createGrpcServer(parentCtx context.Context, cfg config, pool *pgxpool.Pool, u *updater.Updater, field logrus.FieldLogger) *grpc.Server {
	serverOpts := make([]grpc.ServerOption, 0)

	if !strings.HasPrefix(cfg.ListenAddr, "localhost") {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(auth.TokenInterceptor(cfg.RequiredAudience, cfg.AuthorizedServiceAccounts, field.WithField("subsystem", "auth"))))
	}

	grpcServer := grpc.NewServer(serverOpts...)
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, grpcvulnerabilities.NewServer(pool, field.WithField("subsystem", "vulnerabilities")))
	management.RegisterManagementServer(grpcServer, grpcmgmt.NewServer(parentCtx, pool, u, field.WithField("subsystem", "management")))

	return grpcServer
}
