package commands

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/rodaine/table"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

func GetCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	return []*cli.Command{
		{
			Name:    "get",
			Aliases: []string{"g"},
			Usage:   "vulnerability statistics",
			Commands: []*cli.Command{
				{
					Name:    "summary",
					Aliases: []string{"s"},
					Usage:   "get vulnerability summary for filter",
					Flags:   flag.CommonFlags(opts),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getSummary(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "timeseries",
					Aliases: []string{"t"},
					Usage:   "get vulnerability summary time series for filter",
					Flags:   flag.CommonFlags(opts),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getTimeSeries(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "sbom",
					Aliases: []string{"sb"},
					Usage:   "download sbom. Pass an image reference (e.g. ghcr.io/org/image:tag) to fetch from the registry, or use --from-server with --workload to fetch from the v13s server",
					Flags: append(flag.CommonFlags(opts, "limit", "order", "since"),
						&cli.BoolFlag{
							Name:        "from-server",
							Usage:       "fetch sbom from v13s server instead of the registry",
							Destination: &opts.FromServer,
						},
					),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return downloadSbom(ctx, cmd, c, opts)
					},
				},
			},
		},
	}
}

func getSummary(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	opts := flag.ParseOptions(cmd, o)
	start := time.Now()
	resp, err := c.GetVulnerabilitySummary(ctx, opts...)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Workload Count", "SBOM Count", "Critical", "High", "Medium", "Low", "Unassigned", "Risk Score", "Coverage", "Missing SBOMs", "Last Updated")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	tbl.AddRow(
		resp.GetWorkloadCount(),
		resp.GetSbomCount(),
		resp.GetVulnerabilitySummary().GetCritical(),
		resp.GetVulnerabilitySummary().GetHigh(),
		resp.GetVulnerabilitySummary().GetMedium(),
		resp.GetVulnerabilitySummary().GetLow(),
		resp.GetVulnerabilitySummary().GetUnassigned(),
		resp.GetVulnerabilitySummary().GetRiskScore(),
		resp.GetCoverage(),
		resp.GetWorkloadCount()-resp.GetSbomCount(),
		resp.GetVulnerabilitySummary().LastUpdated.AsTime().Format(time.RFC3339),
	)

	tbl.Print()
	fmt.Println("\nFetched summary in", time.Since(start).Seconds(), "seconds")

	return nil
}

func getTimeSeries(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	opts := flag.ParseOptions(cmd, o)
	format := time.DateOnly
	start := time.Now()

	resp, err := c.GetVulnerabilitySummaryTimeSeries(ctx, opts...)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	headers := []any{
		"BucketTime",
		"Critical",
		"High",
		"Medium",
		"Low",
		"Unassigned",
		"RiskScore",
		"WorkloadCount",
	}
	tbl := table.New(headers...)
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, p := range resp.GetPoints() {
		vals := []any{
			p.GetBucketTime().AsTime().Format(format),
			p.GetCritical(),
			p.GetHigh(),
			p.GetMedium(),
			p.GetLow(),
			p.GetUnassigned(),
			p.GetRiskScore(),
			p.GetWorkloadCount(),
		}
		tbl.AddRow(
			vals...,
		)
	}

	tbl.Print()
	duration := time.Since(start).Seconds()
	fmt.Printf("Fetched %d points in %f seconds.\n", len(resp.GetPoints()), duration)
	return nil
}

func downloadSbom(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	if o.FromServer {
		return downloadSbomFromServer(ctx, cmd, c, o)
	}
	return downloadSbomFromRegistry(ctx, cmd)
}

func downloadSbomFromServer(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	opts := flag.ParseOptions(cmd, o)
	if o.Workload == "" {
		return fmt.Errorf("--workload is required when using --from-server")
	}

	resp, err := c.GetSbom(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to get sbom: %w", err)
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, resp.Sbom, "", "  "); err != nil {
		fmt.Println(string(resp.Sbom))
		return nil
	}
	fmt.Println(pretty.String())
	return nil
}

func downloadSbomFromRegistry(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() == 0 {
		return fmt.Errorf("missing image reference (e.g. ghcr.io/org/image:tag)")
	}
	verifier, err := attestation.NewVerifier(ctx, log.WithField("cmd", "sbom"), "nais", "navikt")
	if err != nil {
		return err
	}
	att, err := verifier.GetAttestation(ctx, cmd.Args().First())
	if err != nil {
		return err
	}
	if att == nil {
		return fmt.Errorf("no attestation found for image %s", cmd.Args().First())
	}

	raw := att.Predicate

	// Try base64 decode first (older attestation format)
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(raw), `"`, ""))
	if err == nil {
		raw = decoded
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		fmt.Println(string(raw))
		return nil
	}
	fmt.Println(pretty.String())
	return nil
}
