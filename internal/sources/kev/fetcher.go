package kev

import (
	"context"
	"fmt"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/sirupsen/logrus"
)

type Fetcher struct {
	client  *Client
	querier sql.Querier
	log     *logrus.Entry
}

func NewFetcherWithClient(client *Client, querier sql.Querier, log *logrus.Entry) *Fetcher {
	return &Fetcher{
		client:  client,
		querier: querier,
		log:     log,
	}
}

func (f *Fetcher) Sync(ctx context.Context) error {
	f.log.Info("fetching KEV catalog from CISA")
	result, err := f.client.FetchCatalog(ctx)
	if err != nil {
		return fmt.Errorf("fetching KEV catalog: %w", err)
	}

	catalog := result.Catalog
	f.log.Infof("KEV catalog: %d entries, version %s, released %s",
		catalog.Count, catalog.CatalogVersion, catalog.DateReleased)

	if len(catalog.Vulnerabilities) == 0 {
		f.log.Warn("KEV catalog is empty, nothing to update")
		return nil
	}

	cveIDs := make([]string, 0, len(catalog.Vulnerabilities))
	ransomware := make([]bool, 0, len(catalog.Vulnerabilities))
	ransomwareCount := 0

	for _, v := range catalog.Vulnerabilities {
		cveIDs = append(cveIDs, v.CveID)
		kr := v.KnownRansomware()
		ransomware = append(ransomware, kr)
		if kr {
			ransomwareCount++
		}
	}

	f.log.Infof("updating DB: %d CVEs in catalog (%d with known ransomware use)", len(cveIDs), ransomwareCount)

	updated, err := f.querier.BulkUpdateKevData(ctx, sql.BulkUpdateKevDataParams{
		CveIds:             cveIDs,
		KnownRansomwareUse: ransomware,
	})
	if err != nil {
		return fmt.Errorf("bulk updating KEV data: %w", err)
	}

	f.log.Infof("KEV sync complete: %d CVEs in catalog, %d rows updated in DB", len(cveIDs), updated)
	return nil
}
