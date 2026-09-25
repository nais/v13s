package kev

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

const KevSyncLockKey = int64(7705370002)

type Fetcher struct {
	sources []Source
	pool    *pgxpool.Pool
	querier sql.Querier
	log     *logrus.Entry
}

func NewFetcher(pool *pgxpool.Pool, log *logrus.Entry, sources ...Source) *Fetcher {
	return &Fetcher{sources: sources, pool: pool, log: log}
}

func NewFetcherWithQuerier(querier sql.Querier, log *logrus.Entry, sources ...Source) *Fetcher {
	return &Fetcher{sources: sources, querier: querier, log: log}
}

func (f *Fetcher) Sync(ctx context.Context) error {
	if len(f.sources) == 0 {
		f.log.Warn("no KEV sources configured, skipping KEV sync")
		return nil
	}

	var querier sql.Querier
	var conn *pgxpool.Conn
	if f.pool != nil {
		var err error
		conn, err = f.pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("acquiring DB connection for KEV sync: %w", err)
		}
		querier = sql.New(conn)
	} else {
		querier = f.querier
	}

	locked, err := querier.TryAdvisoryLock(ctx, KevSyncLockKey)
	if err != nil {
		if conn != nil {
			conn.Release()
		}
		return fmt.Errorf("acquiring KEV sync advisory lock: %w", err)
	}
	if !locked {
		if conn != nil {
			conn.Release()
		}
		f.log.Info("KEV sync already running on another pod, skipping")
		return nil
	}

	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		released, unlockErr := querier.AdvisoryUnlock(unlockCtx, KevSyncLockKey)
		if unlockErr != nil {
			f.log.WithError(unlockErr).Warn("failed to release KEV sync advisory lock, discarding connection")
			if conn != nil {
				if closeErr := conn.Hijack().Close(context.Background()); closeErr != nil {
					f.log.WithError(closeErr).Warn("failed to close connection after advisory unlock failure")
				}
			}
			return
		}
		if !released {
			f.log.Warn("KEV sync advisory lock was not held at unlock time")
		}
		if conn != nil {
			conn.Release()
		}
	}()

	return f.sync(ctx, querier)
}

func (f *Fetcher) sync(ctx context.Context, querier sql.Querier) error {
	bySource := make(map[string][]Assertion, len(f.sources))
	var failed []error
	for _, s := range f.sources {
		assertions, err := s.Fetch(ctx)
		if err != nil {
			f.log.WithError(err).Warnf("KEV source %s failed, keeping its previous data", s.Name())
			failed = append(failed, fmt.Errorf("fetching KEV source %s: %w", s.Name(), err))
			continue
		}
		valid := make([]Assertion, 0, len(assertions))
		for _, assertion := range assertions {
			if strings.TrimSpace(assertion.CveID) != "" {
				valid = append(valid, assertion)
			}
		}
		if len(valid) == 0 {
			f.log.Warnf("KEV source %s returned no valid CVE entries, keeping its previous data", s.Name())
			failed = append(failed, fmt.Errorf("KEV source %s returned no valid CVE entries", s.Name()))
			continue
		}
		if len(valid) != len(assertions) {
			f.log.Warnf("KEV source %s returned %d entries without a CVE ID, ignoring them", s.Name(), len(assertions)-len(valid))
		}
		f.log.Infof("KEV source %s: %d entries", s.Name(), len(valid))
		bySource[s.Name()] = valid
	}

	params := entries(bySource)
	if len(params.CveIds) == 0 {
		f.log.Warn("no KEV entries fetched, nothing to update")
		return errors.Join(failed...)
	}

	upserted, err := querier.UpsertKevSourceEntries(ctx, params)
	if err != nil {
		return fmt.Errorf("upserting KEV source entries: %w", err)
	}

	refreshed, err := querier.RefreshCveKevFlags(ctx)
	if err != nil {
		return fmt.Errorf("refreshing cve KEV flags: %w", err)
	}

	prioritiesUpdated, err := querier.UpdateCvePriority(ctx)
	if err != nil {
		return fmt.Errorf("updating cve priority after KEV sync: %w", err)
	}

	f.log.Infof("KEV sync complete: %d source entries upserted, %d CVE KEV flags changed, %d priorities updated", upserted, refreshed, prioritiesUpdated)
	return errors.Join(failed...)
}
