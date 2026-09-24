package kev

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/nais/v13s/internal/httpclient"
)

const SourceVulnCheck = "vulncheck"

type vulnCheckBackupFile struct {
	URL    string `json:"url"`
	Sha256 string `json:"sha256"`
}

type vulnCheckBackup struct {
	Data []vulnCheckBackupFile `json:"data"`
}

type vulnCheckEntry struct {
	Cve                        []string `json:"cve"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
}

type VulnCheckClient struct {
	http   httpclient.Doer
	apiURL string
	token  string
}

func NewVulnCheckClient(apiURL, token string) *VulnCheckClient {
	return &VulnCheckClient{
		http:   httpclient.New(5 * time.Minute),
		apiURL: strings.TrimSuffix(apiURL, "/"),
		token:  token,
	}
}

func (c *VulnCheckClient) Name() string { return SourceVulnCheck }

func (c *VulnCheckClient) Fetch(ctx context.Context) ([]Assertion, error) {
	file, err := c.backupFile(ctx)
	if err != nil {
		return nil, err
	}

	archive, err := httpclient.Get(ctx, c.http, file.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("downloading VulnCheck KEV backup: %w", err)
	}
	sum := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), file.Sha256) {
		return nil, fmt.Errorf("VulnCheck KEV backup checksum mismatch")
	}

	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("opening VulnCheck KEV backup: %w", err)
	}

	var assertions []Assertion
	for _, f := range zr.File {
		if path.Ext(f.Name) != ".json" {
			continue
		}
		entries, err := readVulnCheckEntries(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s from VulnCheck KEV backup: %w", f.Name, err)
		}
		for _, e := range entries {
			for _, cve := range e.Cve {
				assertions = append(assertions, Assertion{
					CveID:           cve,
					KnownRansomware: strings.EqualFold(e.KnownRansomwareCampaignUse, "Known"),
				})
			}
		}
	}
	return assertions, nil
}

func (c *VulnCheckClient) backupFile(ctx context.Context) (vulnCheckBackupFile, error) {
	header := http.Header{"Authorization": []string{"Bearer " + c.token}}

	var backup vulnCheckBackup
	if err := httpclient.GetJSON(ctx, c.http, c.apiURL+"/v3/backup/vulncheck-kev", header, &backup); err != nil {
		return vulnCheckBackupFile{}, fmt.Errorf("requesting VulnCheck KEV backup: %w", err)
	}
	if len(backup.Data) == 0 || backup.Data[0].URL == "" || backup.Data[0].Sha256 == "" {
		return vulnCheckBackupFile{}, fmt.Errorf("VulnCheck KEV backup response has no download URL or checksum")
	}
	return backup.Data[0], nil
}

func readVulnCheckEntries(f *zip.File) ([]vulnCheckEntry, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	return decodeVulnCheckEntries(rc)
}

// decodeVulnCheckEntries accepts a JSON array or a stream of objects.
func decodeVulnCheckEntries(r io.Reader) ([]vulnCheckEntry, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}

	var entries []vulnCheckEntry
	if tok == json.Delim('[') {
		for dec.More() {
			var e vulnCheckEntry
			if err := dec.Decode(&e); err != nil {
				return nil, err
			}
			entries = append(entries, e)
		}

		// Consume the closing ] so a truncated array is rejected.
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return entries, nil
	}

	if tok != json.Delim('{') {
		return nil, fmt.Errorf("unexpected JSON token %v", tok)
	}
	dec = json.NewDecoder(io.MultiReader(strings.NewReader("{"), dec.Buffered(), r))
	for {
		var e vulnCheckEntry
		if err := dec.Decode(&e); errors.Is(err, io.EOF) {
			return entries, nil
		} else if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
}
