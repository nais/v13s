package cveexplanation

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type catalogFunc func(context.Context) (map[string]Input, error)

func (f catalogFunc) Fetch(ctx context.Context) (map[string]Input, error) { return f(ctx) }

type clientFunc func(context.Context, Input) (Explanation, error)

func (f clientFunc) Explain(ctx context.Context, input Input) (Explanation, error) {
	return f(ctx, input)
}

type memoryStore struct {
	candidates []*sql.ListCveExplanationCandidatesRow
	mu         sync.Mutex
	saved      []sql.SaveCveExplanationParams
	begun      []sql.BeginCveExplanationAttemptParams
}

func (s *memoryStore) ListCveExplanationCandidates(context.Context, sql.ListCveExplanationCandidatesParams) ([]*sql.ListCveExplanationCandidatesRow, error) {
	return s.candidates, nil
}

func (s *memoryStore) BeginCveExplanationAttempt(_ context.Context, p sql.BeginCveExplanationAttemptParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.begun = append(s.begun, p)
	return nil
}

func (s *memoryStore) SaveCveExplanation(_ context.Context, p sql.SaveCveExplanationParams) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = append(s.saved, p)
	return 1, nil
}

func newTestGenerator(n int) (*Generator, *memoryStore) {
	inputs := map[string]Input{}
	store := &memoryStore{}
	for i := range n {
		input := publicInput()
		input.CveID = fmt.Sprintf("CVE-2024-%04d", 1000+i)
		inputs[input.CveID] = input
		store.candidates = append(store.candidates, &sql.ListCveExplanationCandidatesRow{CveID: input.CveID, InputHash: input.hash()})
	}
	return &Generator{
		store: store, config: config.ExplanationConfig{MaxPerRun: int32(n), Concurrency: 2, Model: "gemini-test"},
		catalog: catalogFunc(func(context.Context) (map[string]Input, error) { return inputs, nil }),
		client: clientFunc(func(context.Context, Input) (Explanation, error) {
			return Explanation{Summary: "Forklaring", Action: "Følg advisoryen"}, nil
		}),
		log: logrus.NewEntry(logrus.New()),
	}, store
}

func TestGeneratorCallBudgetIncludesRetries(t *testing.T) {
	g, store := newTestGenerator(20)
	g.config.MaxPerRun = 5
	var calls atomic.Int32
	g.client = clientFunc(func(context.Context, Input) (Explanation, error) {
		calls.Add(1)
		return Explanation{}, modelError{code: 429}
	})
	require.Error(t, g.generate(t.Context()))
	require.LessOrEqual(t, calls.Load(), int32(5))
	require.Greater(t, calls.Load(), int32(0))
	require.Empty(t, store.saved)
}

func TestGeneratorFailuresDoNotBlockOtherCandidates(t *testing.T) {
	g, store := newTestGenerator(3)
	g.client = clientFunc(func(_ context.Context, input Input) (Explanation, error) {
		if input.CveID == "CVE-2024-1000" {
			return Explanation{}, modelError{code: 400}
		}
		return Explanation{Summary: "Forklaring", Action: "Følg advisoryen"}, nil
	})
	require.Error(t, g.generate(t.Context()))
	require.Len(t, store.saved, 2)
}

func TestGeneratorRetriesTransientFailureOnce(t *testing.T) {
	g, store := newTestGenerator(1)
	g.config.MaxPerRun = 2
	var calls atomic.Int32
	g.client = clientFunc(func(context.Context, Input) (Explanation, error) {
		if calls.Add(1) == 1 {
			return Explanation{}, modelError{code: 503}
		}
		return Explanation{Summary: "Forklaring", Action: "Følg advisoryen"}, nil
	})
	require.NoError(t, g.generate(t.Context()))
	require.Equal(t, int32(2), calls.Load())
	require.Len(t, store.saved, 1)
}

func TestGeneratorBoundsConcurrentCalls(t *testing.T) {
	g, store := newTestGenerator(8)
	var running, maximum atomic.Int32
	g.client = clientFunc(func(context.Context, Input) (Explanation, error) {
		n := running.Add(1)
		for old := maximum.Load(); n > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		running.Add(-1)
		return Explanation{Summary: "Forklaring", Action: "Følg advisoryen"}, nil
	})
	require.NoError(t, g.generate(t.Context()))
	require.LessOrEqual(t, maximum.Load(), int32(2))
	require.Len(t, store.saved, 8)
}

func TestGeneratorRejectsChangedSourceBeforeSaving(t *testing.T) {
	g, store := newTestGenerator(1)
	first := publicInput()
	first.CveID = store.candidates[0].CveID
	var fetches int
	g.catalog = catalogFunc(func(context.Context) (map[string]Input, error) {
		fetches++
		input := first
		if fetches > 1 {
			input.Description = "Corrected description"
		}
		return map[string]Input{input.CveID: input}, nil
	})
	require.NoError(t, g.generate(t.Context()))
	require.Empty(t, store.saved)
}

func TestGeneratorCancellationStopsWork(t *testing.T) {
	g, store := newTestGenerator(10)
	ctx, cancel := context.WithCancel(t.Context())
	g.client = clientFunc(func(context.Context, Input) (Explanation, error) {
		cancel()
		return Explanation{}, ctx.Err()
	})
	require.ErrorIs(t, g.generate(ctx), context.Canceled)
	require.Empty(t, store.saved)
}
