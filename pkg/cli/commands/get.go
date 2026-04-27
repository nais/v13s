package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/rodaine/table"
	"github.com/urfave/cli/v3"
	"google.golang.org/protobuf/types/known/timestamppb"
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
					Name:    "image-summary",
					Aliases: []string{"is"},
					Usage:   "get vulnerability summary for a specific image (format: <image>:<tag>)",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getImageSummary(ctx, cmd, c)
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
		formatLastUpdated(resp.GetVulnerabilitySummary().GetLastUpdated()),
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

func getImageSummary(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client) error {
	if cmd.Args().Len() == 0 {
		return fmt.Errorf("missing image argument, expected format: <image>:<tag>")
	}
	imageRef := cmd.Args().First()
	tagSep := strings.LastIndex(imageRef, ":")
	lastSlash := strings.LastIndex(imageRef, "/")
	if tagSep == -1 || tagSep < lastSlash || tagSep == len(imageRef)-1 {
		return fmt.Errorf("invalid image format: %s, expected format: <image>:<tag>", imageRef)
	}
	imageName, imageTag := imageRef[:tagSep], imageRef[tagSep+1:]

	start := time.Now()
	resp, err := c.GetVulnerabilitySummaryForImage(ctx, imageName, imageTag)
	if err != nil {
		return fmt.Errorf("failed to get image summary: %w", err)
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	// Image-level summary
	fmt.Printf("Image: %s:%s\n", imageName, imageTag)

	sbomStatus := resp.GetSbomStatus().GetStatus()
	if sbomStatus == vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED {
		sbomStatus = vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
	}
	fmt.Printf("SBOM Status: %s\n\n", sbomStatus)

	if sbomStatus == vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM || sbomStatus == vulnerabilities.SbomStatus_SBOM_STATUS_FAILED {
		fmt.Println("No vulnerability data available for this image.")
	} else if s := resp.GetVulnerabilitySummary(); s != nil {
		tbl := table.New("Critical", "High", "Medium", "Low", "Unassigned", "Risk Score", "Last Updated")
		tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
		tbl.AddRow(
			s.GetCritical(),
			s.GetHigh(),
			s.GetMedium(),
			s.GetLow(),
			s.GetUnassigned(),
			s.GetRiskScore(),
			formatLastUpdated(s.GetLastUpdated()),
		)
		tbl.Print()
		fmt.Println()
	}

	fmt.Println("Fetched image summary in", time.Since(start).Seconds(), "seconds")
	return nil
}

func formatLastUpdated(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "N/A"
	}
	return ts.AsTime().Format(time.RFC3339)
}
