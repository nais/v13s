package kev

import (
	"context"
	"strings"

	"github.com/nais/v13s/internal/httpclient"
)

const SourceENISA = "enisa"

type enisaEntry struct {
	CveID            string `json:"cveID"`
	ExploitationType string `json:"exploitationType"`
}

type EnisaClient struct {
	http httpclient.Doer
	url  string
}

func NewEnisaClient(url string) *EnisaClient {
	return &EnisaClient{
		http: httpclient.New(feedTimeout),
		url:  url,
	}
}

func (c *EnisaClient) Name() string { return SourceENISA }

func (c *EnisaClient) Fetch(ctx context.Context) ([]Assertion, error) {
	var entries []enisaEntry
	if err := httpclient.GetJSON(ctx, c.http, c.url, nil, &entries); err != nil {
		return nil, err
	}

	assertions := make([]Assertion, 0, len(entries))
	for _, e := range entries {
		if e.CveID == "" {
			continue
		}
		assertions = append(assertions, Assertion{
			CveID:           e.CveID,
			KnownRansomware: strings.EqualFold(e.ExploitationType, "ransomware"),
		})
	}
	return assertions, nil
}
