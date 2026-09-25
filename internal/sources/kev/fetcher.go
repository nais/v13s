package kev

import (
	"context"
	"errors"
	"fmt"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

type Fetcher struct {
	sources []Source
	querier sql.Querier
	log     *logrus.Entry
}

func NewFetcher(querier sql.Querier, log *logrus.Entry, sources ...Source) *Fetcher {
	return &Fetcher{
		sources: sources,
		querier: querier,
		log:     log,
	}
}

func (f *Fetcher) Sync(ctx context.Context) error {
	if len(f.sources) == 0 {
		f.log.Warn("no KEV sources configured, skipping KEV sync")
		return nil
	}

	bySource := make(map[string][]Assertion, len(f.sources))
	var failed []error
	for _, s := range f.sources {
		assertions, err := s.Fetch(ctx)
		if err != nil {
			f.log.WithError(err).Warnf("KEV source %s failed, keeping its previous data", s.Name())
			failed = append(failed, fmt.Errorf("fetching KEV source %s: %w", s.Name(), err))
			continue
		}
		if len(assertions) == 0 {
			// An empty feed is almost certainly broken; treating the run as complete would reset ransomware flags.
			f.log.Warnf("KEV source %s returned no entries, keeping its previous data", s.Name())
			failed = append(failed, fmt.Errorf("KEV source %s returned no entries", s.Name()))
			continue
		}
		f.log.Infof("KEV source %s: %d entries", s.Name(), len(assertions))
		bySource[s.Name()] = assertions
	}

	params, ransomwareCount := merge(bySource)
	if len(params.CveIds) == 0 {
		f.log.Warn("no KEV entries fetched, nothing to update")
		return errors.Join(failed...)
	}
	params.Complete = len(failed) == 0

	f.log.Infof("updating DB: %d CVEs across KEV sources (%d with known ransomware use)", len(params.CveIds), ransomwareCount)
	updated, err := f.querier.BulkUpdateKevData(ctx, params)
	if err != nil {
		return fmt.Errorf("bulk updating KEV data: %w", err)
	}

	prioritiesUpdated, err := f.querier.UpdateCvePriority(ctx)
	if err != nil {
		return fmt.Errorf("updating cve priority after KEV sync: %w", err)
	}

	f.log.Infof("KEV sync complete: %d CVEs, %d rows updated in DB, %d priorities updated", len(params.CveIds), updated, prioritiesUpdated)
	return errors.Join(failed...)
}
