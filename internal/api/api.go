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
	"github.com/nais/v13s/internal/api/auth"
	"github.com/nais/v13s/internal/api/grpcmgmt"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/leaderelection"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

func Run(ctx context.Context, cfg *config.Config, log logrus.FieldLogger) error {
	ctx, signalStop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer signalStop()

	if err := leaderelection.Start(ctx, cfg.LeaderElection, log.WithField("subsystem", "leaderelection")); err != nil {
		return fmt.Errorf("starting leader election: %w", err)
	}

	log.Info("Initializing database")
	pool, err := database.New(ctx, cfg.DatabaseUrl, log.WithField("subsystem", "database"))
	if err != nil {
		log.Fatalf("Failed to create database pool: %v", err)
	}
	defer pool.Close()

	source, err := sources.New(cfg.DependencyTrack, log)
	if err != nil {
		log.Fatalf("Failed to create source: %v", err)
	}

	workloadEventQueue := &kubernetes.WorkloadEventQueue{
		Updated: make(chan *model.Workload, 10000),
		Deleted: make(chan *model.Workload, 10000),
	}

	gFunc := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "v13s_workload_update_queue_length",
	}, func() float64 {
		return float64(len(workloadEventQueue.Updated))
	})

	_, tp, promReg, err := metrics.NewMeterProvider(ctx, gFunc)
	if err != nil {
		return fmt.Errorf("create metric meter: %w", err)
	}
	defer func() {
		if tp == nil {
			log.Warn("No tracer provider to shut down")
			return
		}
		if err = tp.Shutdown(ctx); err != nil {
			log.WithError(err).Warn("Failed to shut down tracer provider")
		}
	}()

	verifier, err := attestation.NewVerifier(ctx, log.WithField("subsystem", "verifier"), cfg.GithubOrganizations...)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	jobCfg := &job.Config{
		DbUrl: cfg.DatabaseUrl,
	}

	mgr := manager.NewWorkloadManager(ctx, pool, jobCfg, verifier, source, workloadEventQueue, log.WithField("subsystem", "manager"))
	mgr.Start(ctx)
	defer mgr.Stop(ctx)

	informerMgr, err := kubernetes.NewInformerManager(ctx, cfg.Tenant, cfg.K8s, workloadEventQueue, log.WithField("subsystem", "k8s_watcher"))
	if err != nil {
		log.Fatalf("Failed to create informer manager: %v", err)
	}
	defer informerMgr.Stop()

	syncCtx, cancelSync := context.WithTimeout(ctx, 60*time.Second)
	defer cancelSync()
	if !informerMgr.WaitForReady(syncCtx) {
		log.Fatalf("timed out waiting for watchers to be ready")
	}

	u := updater.NewUpdater(
		pool,
		source,
		mgr,
		updater.ScheduleConfig{
			Type:     updater.SchedulerInterval,
			Interval: cfg.UpdateInterval,
		},
		nil,
		log.WithField("subsystem", "updater"),
	)
	u.Run(ctx)

	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error {
		if err = runGrpcServer(ctx, cfg, pool, mgr, u, log); err != nil {
			log.WithError(err).Errorf("error in GRPC server")
			return err
		}
		return nil
	})

	wg.Go(func() error {
		return runInternalHTTPServer(
			ctx,
			cfg.InternalListenAddr,
			promReg,
			pool,
			log,
			Handler{"/riverui", riverUI(ctx, jobCfg.DbUrl)},
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

func runGrpcServer(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, mgr *manager.WorkloadManager, u *updater.Updater, log logrus.FieldLogger) error {
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
	management.RegisterManagementServer(s, grpcmgmt.NewServer(ctx, pool, mgr, u, log.WithField("subsystem", "management")))

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
