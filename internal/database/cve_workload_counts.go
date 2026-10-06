package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

const cveWorkloadCountsRefreshLockKey = int64(7705370003)

type CveWorkloadCountsRefresher struct {
	pool *pgxpool.Pool
	log  *logrus.Entry
}

func NewCveWorkloadCountsRefresher(pool *pgxpool.Pool, log *logrus.Entry) *CveWorkloadCountsRefresher {
	return &CveWorkloadCountsRefresher{pool: pool, log: log}
}

func (r *CveWorkloadCountsRefresher) Refresh(ctx context.Context) error {
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring DB connection for CVE workload counts refresh: %w", err)
	}
	querier := sql.New(conn)

	locked, err := querier.TryAdvisoryLock(ctx, cveWorkloadCountsRefreshLockKey)
	if err != nil {
		conn.Release()
		return fmt.Errorf("acquiring CVE workload counts refresh advisory lock: %w", err)
	}
	if !locked {
		conn.Release()
		r.log.Info("CVE workload counts refresh already running on another pod, skipping trigger")
		return nil
	}

	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		released, unlockErr := querier.AdvisoryUnlock(unlockCtx, cveWorkloadCountsRefreshLockKey)
		if unlockErr != nil || !released {
			r.log.WithError(unlockErr).Warn("failed to release CVE workload counts refresh advisory lock, discarding connection")
			if closeErr := conn.Hijack().Close(context.Background()); closeErr != nil {
				r.log.WithError(closeErr).Warn("failed to close connection after advisory unlock failure")
			}
			return
		}
		conn.Release()
	}()

	now := time.Now()
	if err := querier.RefreshCveWorkloadCounts(ctx); err != nil {
		return fmt.Errorf("refreshing CVE workload counts: %w", err)
	}
	r.log.Infof("CVE workload counts refreshed, took %f seconds", time.Since(now).Seconds())
	return nil
}
