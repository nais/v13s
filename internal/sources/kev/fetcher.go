package kev

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

type Fetcher struct {
	client  *Client
	querier sql.Querier
	log     *logrus.Entry
}

func NewFetcher(querier sql.Querier, log *logrus.Entry) *Fetcher {
	return &Fetcher{
		client:  NewClient(),
		querier: querier,
		log:     log,
	}
}

func NewFetcherWithClient(client *Client, querier sql.Querier, log *logrus.Entry) *Fetcher {
	return &Fetcher{
		client:  client,
		querier: querier,
		log:     log,
	}
}

func (f *Fetcher) Sync(ctx context.Context) error {
	lastETag := ""
	state, err := f.querier.GetKevSyncState(ctx)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("reading KEV sync state: %w", err)
	}
	if state != nil {
		lastETag = state.Etag
	}

	result, err := f.client.FetchCatalog(ctx)
	if err != nil {
		return fmt.Errorf("fetching KEV catalog: %w", err)
	}

	if result.ETag != "" && result.ETag == lastETag {
		f.log.Infof("KEV catalog unchanged (ETag %s), skipping sync", result.ETag)
		return nil
	}

	catalog := result.Catalog
	f.log.Infof("KEV catalog downloaded: %d entries (version %s)", catalog.Count, catalog.CatalogVersion)

	if len(catalog.Vulnerabilities) == 0 {
		f.log.Warn("KEV catalog is empty, nothing to update")
		return nil
	}

	cveIDs := make([]string, 0, len(catalog.Vulnerabilities))
	ransomware := make([]bool, 0, len(catalog.Vulnerabilities))

	for _, v := range catalog.Vulnerabilities {
		cveIDs = append(cveIDs, v.CveID)
		ransomware = append(ransomware, v.KnownRansomware())
	}

	if err := f.querier.BulkUpdateKevData(ctx, sql.BulkUpdateKevDataParams{
		CveIds:             cveIDs,
		KnownRansomwareUse: ransomware,
	}); err != nil {
		return fmt.Errorf("bulk updating KEV data: %w", err)
	}

	if err := f.querier.UpsertKevSyncState(ctx, result.ETag); err != nil {
		return fmt.Errorf("persisting KEV sync state: %w", err)
	}

	f.log.Infof("KEV data synced: %d CVEs processed", len(cveIDs))
	return nil
}
