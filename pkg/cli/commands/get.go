package commands

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/rodaine/table"
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
					Name:  "sbom-status",
					Usage: "get SBOM status for an image",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getImageSbomStatus(ctx, cmd, c)
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

func getImageSbomStatus(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client) error {
	imageName, imageTag, err := getImage(cmd)
	if err != nil {
		return err
	}

	resp, err := c.GetImageSbomStatus(ctx, imageName, imageTag)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	vulnTbl := table.New("Image Name", "Image Tag", "SBOM Present", "Last Updated")
	vulnTbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	vulnTbl.AddRow(
		imageName,
		imageTag,
		strconv.FormatBool(resp.GetSbomStatus().GetSbomPresent()),
		timeSinceCreation(resp.GetSbomStatus().GetUpdatedAt().AsTime(), time.Now()),
	)
	vulnTbl.Print()
	return nil
}
