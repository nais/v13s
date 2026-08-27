package api

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/api/auth"
	"github.com/nais/v13s/internal/api/grpcmgmt"
	"github.com/nais/v13s/internal/api/grpcvulnerabilities"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database"
	dbsql "github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/resync"
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
		Namespace: metrics.Namespace,
		Subsystem: metrics.Subsystem,
		Name:      "workload_update_queue_length",
	}, func() float64 {
		return float64(len(workloadEventQueue.Updated))
	})

	tp, promReg, err := metrics.NewMeterProvider(ctx, cfg.Metrics, log.WithField("subsystem", "metrics-setup"), gFunc)
	if err != nil {
		return fmt.Errorf("create metric meter: %w", err)
	}
	defer func() {
		if tp == nil {
			log.Warn("No tracer provider to shut down")
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = tp.Shutdown(shutdownCtx); err != nil {
			log.WithError(err).Warn("Failed to shut down tracer provider")
		}
	}()

	if err = metrics.LoadWorkloadMetrics(ctx, pool, log.WithField("subsystem", "metrics-load")); err != nil {
		log.WithError(err).Error("failed to load metrics from DB")
	}

	metrics.StartWorkloadMetricsRefresher(
		ctx,
		pool,
		cfg.Metrics.WorkloadMetricsRefreshDuration,
		log.WithField("subsystem", "metrics-refresh"),
	)

	if cfg.Metrics.PrometheusMetricsPushgatewayEndpoint != "" {
		go metrics.PushOnce(cfg.Metrics, promReg, log)
		metrics.StartIntervalPusher(ctx, cfg.Metrics, promReg, log)
	} else {
		log.Info("Prometheus Pushgateway endpoint not configured, skipping metrics push setup")
	}

	verifier, err := attestation.NewVerifier(ctx, log.WithField("subsystem", "verifier"), cfg.GithubOrganizations...)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	jobCfg := &job.Config{
		DbUrl: cfg.DatabaseUrl,
	}

	ready := &atomic.Bool{}

	httpErrCh := make(chan error, 1)
	go func() {
		httpErrCh <- runInternalHTTPServer(
			ctx,
			cfg.InternalListenAddr,
			promReg,
			pool,
			ready,
			log,
			Handler{"/riverui", riverUI(ctx, jobCfg.DbUrl)},
		)
	}()

	mgr := manager.NewWorkloadManager(ctx, pool, jobCfg, verifier, source, workloadEventQueue, cfg.ReconcileDeletionEnabled, log.WithField("subsystem", "manager"))
	if cfg.ReconcileDeletionEnabled {
		log.Info("workload reconciliation: enabled — orphaned workloads will be deleted")
	} else {
		log.Info("workload reconciliation: dry-run — orphaned workloads will be logged but not deleted (set RECONCILE_DELETION_ENABLED=true to enable)")
	}
	if err := mgr.Start(ctx); err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := mgr.Stop(stopCtx); err != nil {
			log.WithError(err).Error("failed to stop workload manager")
		}
	}()

	informerMgr, err := kubernetes.NewInformerManager(ctx, cfg.Tenant, cfg.K8s, workloadEventQueue, log.WithField("subsystem", "k8s_watcher"))
	if err != nil {
		log.Fatalf("Failed to create informer manager: %v", err)
	}
	defer informerMgr.Stop()

	syncCtx, cancelSync := context.WithTimeout(ctx, 60*time.Second)
	defer cancelSync()

	syncDone := make(chan bool, 1)
	go func() {
		syncDone <- informerMgr.WaitForReady(syncCtx)
	}()

	select {
	case err := <-httpErrCh:
		if ctx.Err() != nil {
			// SIGTERM/SIGINT arrived before watchers synced — this is a clean shutdown, not a crash.
			return nil
		}
		return fmt.Errorf("HTTP server failed before watchers became ready: %w", err)
	case ready := <-syncDone:
		if !ready {
			if ctx.Err() != nil {
				return fmt.Errorf("context cancelled before watchers became ready: %w", ctx.Err())
			}
			log.Fatalf("timed out waiting for watchers to be ready")
		}
	}

	log.Info("reconciling workloads against k8s state")
	mgr.ReconcileWorkloads(ctx, informerMgr.ListWorkloadsByCluster())

	runtimeCfg := updater.DefaultRuntimeConfig(updater.ScheduleConfig{
		Type:     updater.SchedulerInterval,
		Interval: cfg.UpdateInterval,
	})
	runtimeCfg.OrchestrationEnabled = cfg.Updater.RuntimeOrchestrationEnabled
	runtimeCfg.Resync.Enabled = cfg.Updater.ResyncEnabled
	runtimeCfg.MarkUnused = updater.JobRuntimeConfig{
		Enabled: cfg.Updater.MarkUnusedEnabled,
		Schedule: updater.ScheduleConfig{
			Type:     updater.SchedulerCron,
			CronExpr: cfg.Updater.MarkUnusedCron,
		},
	}
	runtimeCfg.MarkUntracked = updater.JobRuntimeConfig{
		Enabled: cfg.Updater.MarkUntrackedEnabled,
		Schedule: updater.ScheduleConfig{
			Type:     updater.SchedulerCron,
			CronExpr: cfg.Updater.MarkUntrackedCron,
		},
	}
	runtimeCfg.RefreshDailySummary = updater.JobRuntimeConfig{
		Enabled: cfg.Updater.RefreshSummaryEnabled,
		Schedule: updater.ScheduleConfig{
			Type:     updater.SchedulerCron,
			CronExpr: cfg.Updater.RefreshSummaryCron,
		},
	}
	runtimeCfg.RefreshWorkloadLifetimes = updater.JobRuntimeConfig{
		Enabled: cfg.Updater.RefreshLifetimesEnabled,
		Schedule: updater.ScheduleConfig{
			Type:     updater.SchedulerCron,
			CronExpr: cfg.Updater.RefreshLifetimesCron,
		},
	}
	runtimeCfg.SyncKev = updater.JobRuntimeConfig{
		Enabled: cfg.Updater.SyncKevEnabled,
		Schedule: updater.ScheduleConfig{
			Type:     updater.SchedulerCron,
			CronExpr: cfg.Updater.SyncKevCron,
		},
	}
	runtimeCfg.SyncOsv = updater.JobRuntimeConfig{
		Enabled: cfg.Updater.SyncOsvEnabled,
		Schedule: updater.ScheduleConfig{
			Type:     updater.SchedulerCron,
			CronExpr: cfg.Updater.SyncOsvCron,
		},
	}
	runtimeCfg.RekeySuppressedAliases = updater.JobRuntimeConfig{
		Enabled: cfg.Updater.RekeySuppressedEnabled,
		Schedule: updater.ScheduleConfig{
			Type:     updater.SchedulerCron,
			CronExpr: cfg.Updater.RekeySuppressedCron,
		},
	}

	u := updater.NewUpdaterWithRuntimeConfig(
		pool,
		source,
		log.WithField("subsystem", "updater"),
		cfg.Kev,
		cfg.Osv,
		runtimeCfg,
	)
	u.Start(ctx)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := u.Stop(stopCtx); err != nil {
			log.WithError(err).Error("failed to stop updater")
		}
	}()

	resyncModule := resync.NewWorkloadResyncModule(ctx, dbsql.New(pool), mgr, u, log.WithField("subsystem", "workload_resync"))

	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error {
		select {
		case err := <-httpErrCh:
			return err
		case <-ctx.Done():
			return nil
		}
	})

	wg.Go(func() error {
		if err = runGrpcServer(ctx, cfg, pool, mgr, resyncModule, log, func() { ready.Store(true) }); err != nil {
			log.WithError(err).Errorf("error in GRPC server")
			return err
		}
		return nil
	})

	<-ctx.Done()
	signalStop()
	log.Infof("shutting down...")

	ch := make(chan error)
	go func() {
		ch <- wg.Wait()
	}()

	select {
	case <-time.After(45 * time.Second):
		log.Warn("timed out waiting for graceful shutdown")
	case err := <-ch:
		return err
	}

	return nil
}

func runGrpcServer(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, mgr *manager.WorkloadManager, resyncModule resync.Module, log logrus.FieldLogger, onReady func()) error {
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
	management.RegisterManagementServer(s, grpcmgmt.NewServer(pool, mgr, resyncModule, log.WithField("subsystem", "management")))

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		onReady()
		return s.Serve(lis)
	})
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
