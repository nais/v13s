package cveexplanation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const explanationLockKey = int64(7705370004)

type store interface {
	ListCveExplanationCandidates(context.Context, sql.ListCveExplanationCandidatesParams) ([]*sql.ListCveExplanationCandidatesRow, error)
	BeginCveExplanationAttempt(context.Context, sql.BeginCveExplanationAttemptParams) error
	SaveCveExplanation(context.Context, sql.SaveCveExplanationParams) (int64, error)
}

type Generator struct {
	pool    *pgxpool.Pool
	store   store
	catalog Catalog
	client  Client
	config  config.ExplanationConfig
	log     *logrus.Entry
}

func NewGenerator(pool *pgxpool.Pool, client Client, cfg config.ExplanationConfig, log *logrus.Entry) *Generator {
	return &Generator{pool: pool, store: sql.New(pool), catalog: NewCisaCatalog(), client: client, config: cfg, log: log}
}

func (g *Generator) Run(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	conn, err := g.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring CVE explanation lock connection: %w", err)
	}
	querier := sql.New(conn)
	locked, err := querier.TryAdvisoryLock(ctx, explanationLockKey)
	if err != nil {
		conn.Release()
		return fmt.Errorf("acquiring CVE explanation lock: %w", err)
	}
	if !locked {
		conn.Release()
		return nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		released, err := querier.AdvisoryUnlock(unlockCtx, explanationLockKey)
		if err != nil || !released {
			g.log.Warn("failed to release CVE explanation lock, discarding connection")
			_ = conn.Hijack().Close(unlockCtx)
			return
		}
		conn.Release()
	}()
	return g.generate(ctx)
}

func (g *Generator) generate(ctx context.Context) error {
	inputs, err := g.catalog.Fetch(ctx)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(inputs))
	for id, input := range inputs {
		if id == input.CveID && input.validate() == nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	hashes := make([]string, len(ids))
	for n, id := range ids {
		hashes[n] = inputs[id].hash()
	}
	candidates, err := g.store.ListCveExplanationCandidates(ctx, sql.ListCveExplanationCandidatesParams{
		CveIds: ids, InputHashes: hashes, PromptVersion: PromptVersion, MaxCandidates: g.config.MaxPerRun,
	})
	if err != nil {
		return fmt.Errorf("listing CVE explanation candidates: %w", err)
	}
	if len(candidates) == 0 {
		return nil
	}

	var attempts atomic.Int32
	reserve := func() bool {
		for {
			n := attempts.Load()
			if n >= g.config.MaxPerRun {
				return false
			}
			if attempts.CompareAndSwap(n, n+1) {
				return true
			}
		}
	}
	type result struct {
		input       Input
		explanation Explanation
	}
	var mu sync.Mutex
	var results []result
	var failures atomic.Int32
	var group errgroup.Group
	group.SetLimit(g.config.Concurrency)
	for _, candidate := range candidates {
		if ctx.Err() != nil || !reserve() {
			break
		}
		input, ok := inputs[candidate.CveID]
		if !ok || input.hash() != candidate.InputHash {
			continue
		}
		if err := g.store.BeginCveExplanationAttempt(ctx, sql.BeginCveExplanationAttemptParams{
			CveID: input.CveID, PromptVersion: PromptVersion, InputHash: input.hash(), SourceUrls: []string{CatalogURL},
		}); err != nil {
			failures.Add(1)
			continue
		}
		group.Go(func() error {
			explanation, err := g.client.Explain(ctx, input)
			var modelErr modelError
			if errors.As(err, &modelErr) && (modelErr.code == 408 || modelErr.code == 429 || modelErr.code >= 500) && reserve() {
				timer := time.NewTimer(time.Second)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
					explanation, err = g.client.Explain(ctx, input)
				}
			}
			if err != nil || explanation.validate() != nil {
				failures.Add(1)
				return nil
			}
			mu.Lock()
			results = append(results, result{input: input, explanation: explanation})
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(results) > 0 {
		current, err := g.catalog.Fetch(ctx)
		if err != nil {
			return err
		}
		for _, result := range results {
			input, ok := current[result.input.CveID]
			if !ok || input.validate() != nil || input.hash() != result.input.hash() {
				continue
			}
			if _, err := g.store.SaveCveExplanation(ctx, sql.SaveCveExplanationParams{
				CveID: input.CveID, InputHash: input.hash(), PromptVersion: PromptVersion,
				Summary: &result.explanation.Summary, Action: &result.explanation.Action, Model: &g.config.Model,
			}); err != nil {
				return fmt.Errorf("saving CVE explanation: %w", err)
			}
		}
	}
	g.log.WithFields(logrus.Fields{"attempts": attempts.Load(), "failures": failures.Load()}).Info("CVE explanation generation finished")
	if failures.Load() > 0 {
		return fmt.Errorf("CVE explanation generation failed for %d candidates", failures.Load())
	}
	return nil
}
