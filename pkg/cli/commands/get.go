package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/helpers"
	"github.com/rodaine/table"
	"github.com/urfave/cli/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
					Name:    "timeseries",
					Aliases: []string{"t"},
					Usage:   "get vulnerability summary time series for filter",
					Flags:   flag.CommonFlags(opts),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getTimeSeries(ctx, cmd, c, opts)
					},
				},
				{
					Name:  "image-summary",
					Usage: "get vulnerability summary and SBOM status for an image (format: <image>:<tag>)",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getImageSummary(ctx, cmd, c)
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

func formatLastUpdated(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "N/A"
	}
	return ts.AsTime().Format(time.RFC3339)
}

func getImageSummary(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client) error {
	if cmd.Args().Len() == 0 {
		return fmt.Errorf("missing image argument, expected format: <image>:<tag>")
	}
	imageName, imageTag, err := helpers.SplitImageRef(cmd.Args().First())
	if err != nil {
		return err
	}

	resp, err := c.GetVulnerabilitySummaryForImage(ctx, imageName, imageTag)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			fmt.Printf("Image: %s:%s — no SBOM found\n", imageName, imageTag)
			return nil
		}
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	s := resp.GetVulnerabilitySummary()
	aggregatedStatus := resp.GetSbomStatus()
	workloads := resp.GetWorkloads()

	isProcessing := aggregatedStatus.GetStatus() == vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING ||
		aggregatedStatus.GetStatus() == vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED

	fmt.Printf("Image: %s:%s\n", imageName, imageTag)
	if s != nil && s.GetHasSbom() {
		staleNote := ""
		if s.GetStaleImageTag() != "" {
			staleNote = fmt.Sprintf(" (from previous tag %s — updating)", s.GetStaleImageTag())
		} else if isProcessing {
			staleNote = " (previous scan — updating)"
		}
		fmt.Printf("Critical: %d  High: %d  Medium: %d  Low: %d  Unassigned: %d  RiskScore: %d%s\n",
			s.GetCritical(), s.GetHigh(), s.GetMedium(), s.GetLow(), s.GetUnassigned(), s.GetRiskScore(), staleNote)
		fmt.Printf("Last Updated: %s\n\n", formatLastUpdated(s.GetLastUpdated()))
	} else if isProcessing {
		fmt.Println("No vulnerability data yet — waiting for first SBOM scan to complete.")
		fmt.Println()
	} else {
		fmt.Printf("No SBOM\n\n")
	}

	if len(workloads) > 0 {
		tbl := table.New("Workload", "Type", "Namespace", "Cluster", "SBOM Status")
		tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
		for _, w := range workloads {
			wl := w.GetWorkload()
			tbl.AddRow(wl.GetName(), wl.GetType(), wl.GetNamespace(), wl.GetCluster(), formatSbomStatus(w.GetSbomStatus()))
		}
		tbl.Print()
	} else {
		fmt.Println("No workloads found for this image.")
	}

	return nil
}
