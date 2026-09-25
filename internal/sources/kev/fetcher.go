package kev

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
