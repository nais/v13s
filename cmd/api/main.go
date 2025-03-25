package main

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/api/auth"
	"github.com/nais/v13s/internal/api/grpcmgmt"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database"
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

	"github.com/nais/v13s/internal/dependencytrack"
	"google.golang.org/grpc"
)

const (
	exitCodeSuccess = iota
	exitCodeLoggerError
	exitCodeRunError
	exitCodeConfigError
)

// handle env vars better
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := logrus.StandardLogger()

	cfg, err := config.NewConfig()
	if err != nil {
		log.WithError(err).Errorf("error when processing configuration")
		os.Exit(exitCodeConfigError)
	}

	appLogger := setupLogger(log, cfg.LogFormat, cfg.LogLevel)
	err = run(ctx, cfg, appLogger)
	if err != nil {
		appLogger.WithError(err).Errorf("error in run()")
		os.Exit(exitCodeRunError)
	}

	os.Exit(exitCodeSuccess)
}

func run(ctx context.Context, cfg *config.Config, log logrus.FieldLogger) error {
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.WithError(err).Fatalf("Failed to listen on %s", cfg.ListenAddr)
	}

	log.Info("Initializing database")

	pool, err := database.New(ctx, cfg.DatabaseUrl, log.WithField("subsystem", "database"))
	if err != nil {
		log.Fatalf("Failed to create database pool: %v", err)
	}
	defer pool.Close()

	dpClient, err := dependencytrack.NewClient(
		cfg.DependencyTrack.Url,
		cfg.DependencyTrack.Team,
		cfg.DependencyTrack.Username,
		cfg.DependencyTrack.Password,
		log.WithField("subsystem", "dp-client"),
	)
	if err != nil {
		log.Fatalf("Failed to create DependencyTrack client: %v", err)
	}

	source := sources.NewDependencytrackSource(dpClient, log.WithField("subsystem", "dependencytrack"))
	u := updater.NewUpdater(pool, source, cfg.UpdateInterval, log.WithField("subsystem", "updater"))
	u.Run(ctx)

	/*
		clusterConfig, err := kubernetes.CreateClusterConfigMap(cfg.Tenant, cfg.K8s.Clusters, cfg.K8s.StaticClusters)
		if err != nil {
			return fmt.Errorf("creating cluster config map: %w", err)
		}

		if cfg.K8s.UseKubeConfig && os.Getenv("KUBECONFIG") != "" {
			envConfig := os.Getenv("KUBECONFIG")
			kubeConfig, err := clientcmd.BuildConfigFromFlags("", envConfig)
			if err != nil {
				return fmt.Errorf("building kubeconfig from flags: %w", err)
			}
			log.Infof("starting with kubeconfig: %s", envConfig)
			watcherMgr, err := watcher.NewManager(clusterConfig, log.WithField("subsystem", "k8s_watcher"))
			if err != nil {
				return fmt.Errorf("create k8s watcher manager: %w", err)
			}

		} else {
			watcherMgr, err := watcher.NewManager(clusterConfig, log.WithField("subsystem", "k8s_watcher"))
			if err != nil {
				return fmt.Errorf("create k8s watcher manager: %w", err)
			}
			mgmtWatcher, err := watcher.NewManager(kubernetes.ClusterConfigMap{"management": nil}, log.WithField("subsystem", "k8s_watcher"))
			if err != nil {
				return fmt.Errorf("create k8s watcher manager for management: %w", err)
			}
		}*/

	grpcServer := createGrpcServer(ctx, cfg, pool, u, log)

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

func createGrpcServer(parentCtx context.Context, cfg *config.Config, pool *pgxpool.Pool, u *updater.Updater, field logrus.FieldLogger) *grpc.Server {
	serverOpts := make([]grpc.ServerOption, 0)

	if !strings.HasPrefix(cfg.ListenAddr, "localhost") {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(auth.TokenInterceptor(cfg.RequiredAudience, cfg.AuthorizedServiceAccounts, field.WithField("subsystem", "auth"))))
	}

	grpcServer := grpc.NewServer(serverOpts...)
	vulnerabilities.RegisterVulnerabilitiesServer(grpcServer, grpcvulnerabilities.NewServer(pool, field.WithField("subsystem", "vulnerabilities")))
	management.RegisterManagementServer(grpcServer, grpcmgmt.NewServer(parentCtx, pool, u, field.WithField("subsystem", "management")))

	return grpcServer
}
