package commands

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/helpers"
	"github.com/nais/v13s/pkg/cli/output"
	"github.com/nais/v13s/pkg/cli/pagination"
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
			Usage:   "get aggregated vulnerability data",
			Commands: []*cli.Command{
				{
					Name:    "summary",
					Aliases: []string{"s"},
					Usage:   "get aggregated vulnerability summary",
					Flags:   flag.CommonFlags(opts, "limit", "order", "since", "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getSummary(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "image",
					Aliases: []string{"i"},
					Usage:   "get vulnerability summary and SBOM status for an image (format: <image>:<tag>)",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getImageSummary(ctx, cmd, c)
					},
				},
				{
					Name:    "cve",
					Aliases: []string{"c"},
					Usage:   "get details for a CVE",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getCve(ctx, cmd, c)
					},
				},
				{
					Name:    "timeseries",
					Aliases: []string{"t"},
					Usage:   "get vulnerability count time series",
					Flags:   flag.CommonFlags(opts, "limit", "order", "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return getTimeSeries(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "status",
					Aliases: []string{"st"},
					Usage:   "get workload processing status",
					Flags: append(flag.CommonFlags(opts, "order", "since", "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
						&cli.BoolFlag{
							Name:        "show-jobs",
							Aliases:     []string{"j"},
							Usage:       "show jobs associated with the workload",
							Destination: &opts.ShowJobs,
						},
					),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						if err := getStatus(ctx, opts, c); err != nil {
							return fmt.Errorf("failed to get workload status: %w", err)
						}
						if opts.ShowJobs {
							if err := getWorkloadJobStatus(ctx, opts, c); err != nil {
								return fmt.Errorf("failed to get workload job status: %w", err)
							}
						}
						return nil
					},
				},
				{
					Name:    "mttf",
					Aliases: []string{"m"},
					Usage:   "get mean time to fix data",
					Commands: []*cli.Command{
						{
							Name:    "workloads",
							Aliases: []string{"w"},
							Usage:   "MTTF per workload and severity",
							Flags:   flag.CommonFlags(opts, "limit", "order", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
							Action: func(ctx context.Context, cmd *cli.Command) error {
								return listWorkloadMTTFBySeverity(ctx, cmd, c, opts)
							},
						},
						{
							Name:    "trend",
							Aliases: []string{"t"},
							Usage:   "MTTF per severity trend over time",
							Flags:   flag.CommonFlags(opts, "limit", "order", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
							Action: func(ctx context.Context, cmd *cli.Command) error {
								return listMeanTimeToFixTrendBySeverity(ctx, cmd, c, opts)
							},
						},
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

	tbl := output.New("Workload Count", "SBOM Count", "Critical", "High", "Medium", "Low", "Unassigned", "Risk Score", "Coverage", "Missing SBOMs", "Last Updated")
	tbl.AddRow(
		fmt.Sprint(resp.GetWorkloadCount()),
		fmt.Sprint(resp.GetSbomCount()),
		fmt.Sprint(resp.GetVulnerabilitySummary().GetCritical()),
		fmt.Sprint(resp.GetVulnerabilitySummary().GetHigh()),
		fmt.Sprint(resp.GetVulnerabilitySummary().GetMedium()),
		fmt.Sprint(resp.GetVulnerabilitySummary().GetLow()),
		fmt.Sprint(resp.GetVulnerabilitySummary().GetUnassigned()),
		fmt.Sprint(resp.GetVulnerabilitySummary().GetRiskScore()),
		fmt.Sprint(resp.GetCoverage()),
		fmt.Sprint(resp.GetWorkloadCount()-resp.GetSbomCount()),
		formatLastUpdated(resp.GetVulnerabilitySummary().GetLastUpdated()),
	)
	tbl.Print()
	fmt.Println("\nFetched summary in", time.Since(start).Seconds(), "seconds")

	return nil
}

func getTimeSeries(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	opts := flag.ParseOptions(cmd, o)
	start := time.Now()

	resp, err := c.GetVulnerabilitySummaryTimeSeries(ctx, opts...)
	if err != nil {
		return err
	}

	tbl := output.New("BucketTime", "Critical", "High", "Medium", "Low", "Unassigned", "RiskScore", "WorkloadCount")

	for _, p := range resp.GetPoints() {
		tbl.AddRow(
			p.GetBucketTime().AsTime().Format(time.DateOnly),
			fmt.Sprint(p.GetCritical()),
			fmt.Sprint(p.GetHigh()),
			fmt.Sprint(p.GetMedium()),
			fmt.Sprint(p.GetLow()),
			fmt.Sprint(p.GetUnassigned()),
			fmt.Sprint(p.GetRiskScore()),
			fmt.Sprint(p.GetWorkloadCount()),
		)
	}

	tbl.Print()
	fmt.Printf("Fetched %d points in %f seconds.\n", len(resp.GetPoints()), time.Since(start).Seconds())
	return nil
}

func getCve(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client) error {
	if cmd.Args().First() == "" {
		return fmt.Errorf("CVE ID is required")
	}

	resp, err := c.GetCve(ctx, cmd.Args().First())
	if err != nil {
		return err
	}

	cvssScore := "N/A"
	if score := resp.Cve.GetCvssScore(); score != 0 {
		cvssScore = fmt.Sprintf("%g", score)
	}

	tbl := output.New("Field", "Value")
	tbl.AddRow("CVE ID", resp.Cve.GetId())
	tbl.AddRow("Severity", resp.Cve.GetSeverity().String())
	tbl.AddRow("CVSS Score", cvssScore)
	tbl.AddRow("Description", resp.Cve.GetDescription())
	tbl.Print()
	return nil
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
			tbl := output.New("Field", "Value")
			tbl.AddRow("Image", fmt.Sprintf("%s:%s", imageName, imageTag))
			tbl.AddRow("SBOM", "not found")
			tbl.Print()
			return nil
		}
		return err
	}

	s := resp.GetVulnerabilitySummary()
	workloads := resp.GetWorkloadRef()
	isProcessing := imageIsProcessing(resp)

	tbl := output.New("Field", "Value")
	tbl.AddRow("Image", fmt.Sprintf("%s:%s", imageName, imageTag))
	tbl.AddRow("SBOM Status", formatSbomStatus(resp.GetSbomStatus()))

	if s != nil && s.GetHasSbom() {
		staleNote := ""
		if s.GetStaleImageTag() != "" {
			staleNote = fmt.Sprintf(" (from previous tag %s — updating)", s.GetStaleImageTag())
		} else if isProcessing {
			staleNote = " (previous scan — updating)"
		}
		tbl.AddRow("Priority Act Now", fmt.Sprint(s.GetPriorityActNow()))
		tbl.AddRow("Priority High", fmt.Sprint(s.GetPriorityHigh()))
		tbl.AddRow("Priority Elevated", fmt.Sprint(s.GetPriorityElevated()))
		tbl.AddRow("Priority Monitor", fmt.Sprint(s.GetPriorityMonitor()))
		tbl.AddRow("Critical", fmt.Sprint(s.GetCritical()))
		tbl.AddRow("High", fmt.Sprint(s.GetHigh()))
		tbl.AddRow("Medium", fmt.Sprint(s.GetMedium()))
		tbl.AddRow("Low", fmt.Sprint(s.GetLow()))
		tbl.AddRow("Unassigned", fmt.Sprint(s.GetUnassigned()))
		tbl.AddRow("Risk Score", fmt.Sprint(s.GetRiskScore()))
		tbl.AddRow("Last Updated", formatLastUpdated(s.GetLastUpdated())+staleNote)
	} else if isProcessing {
		tbl.AddRow("Vulnerabilities", "waiting for first SBOM scan to complete")
	} else {
		tbl.AddRow("Vulnerabilities", "no SBOM")
	}
	tbl.Print()

	if len(workloads) > 0 {
		fmt.Println()
		wtbl := output.New("Workload", "Type", "Namespace", "Cluster")
		for _, w := range workloads {
			wtbl.AddRow(w.GetName(), w.GetType(), w.GetNamespace(), w.GetCluster())
		}
		wtbl.Print()
	} else {
		fmt.Println("No workloads found for this image.")
	}

	return nil
}

func formatLastUpdated(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "N/A"
	}
	return ts.AsTime().Format(time.RFC3339)
}

func getStatus(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	if opts.Limit <= 0 {
		opts.Limit = 30
	}
	cluster, namespace, workload, workloadType := extractFilters(opts)

	return pagination.Paginate(opts.Limit, func(offset int) (int, bool, error) {
		s, err := c.GetWorkloadStatus(ctx, &management.GetWorkloadStatusRequest{
			Cluster:      cluster,
			Namespace:    namespace,
			Workload:     workload,
			WorkloadType: workloadType,
			Limit:        helpers.MustIntToInt32(opts.Limit),
			Offset:       helpers.MustIntToInt32(offset),
		})
		if err != nil {
			return 0, false, fmt.Errorf("failed to get workload status: %w", err)
		}

		tbl := output.New("Workload", "Type", "Namespace", "Cluster", "State", "Image Name", "Image Tag", "Image State")
		for _, ws := range s.WorkloadStatus {
			tbl.AddRow(ws.Workload, ws.WorkloadType, ws.Namespace, ws.Cluster, ws.WorkloadState, ws.ImageName, ws.ImageTag, ws.ImageState)
		}
		tbl.Print()
		return int(s.TotalCount), s.HasNextPage, nil
	})
}

func getWorkloadJobStatus(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	cluster, namespace, workload, _ := extractFilters(opts)

	return pagination.Paginate(opts.Limit, func(offset int) (int, bool, error) {
		s, err := c.GetWorkloadJobs(ctx, &management.GetWorkloadJobsRequest{
			Cluster:   cluster,
			Namespace: namespace,
			Workload:  workload,
			Limit:     helpers.MustIntToInt32(opts.Limit),
			Offset:    helpers.MustIntToInt32(offset),
		})
		if err != nil {
			return 0, false, fmt.Errorf("failed to get workload jobs: %w", err)
		}

		tbl := output.New("Job ID", "Kind", "State", "Metadata", "Attempts", "Errors", "Finished At")
		for _, job := range s.GetJobs() {
			tbl.AddRow(
				strconv.FormatInt(job.Id, 10),
				job.Kind,
				job.State,
				job.Metadata,
				strconv.Itoa(int(job.Attempts)),
				job.Errors,
				job.FinishedAt.AsTime().Format(time.RFC3339),
			)
		}
		tbl.Print()
		return int(s.TotalCount), s.HasNextPage, nil
	})
}

func listWorkloadMTTFBySeverity(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, opts *flag.Options) error {
	resp, err := c.ListWorkloadMTTFBySeverity(ctx, flag.ParseOptions(cmd, opts)...)
	if err != nil {
		return fmt.Errorf("failed to list workload severities with MTTF: %w", err)
	}

	tbl := output.New("Workload", "Namespace", "Severity", "Introduced At", "Fixed At", "Fixed", "Fix Duration (days)", "Fix Count", "Snapshot Date")

	for _, workload := range resp.GetWorkloads() {
		for _, fix := range workload.GetFixes() {
			lastFixed := "N/A"
			if fix.FixedAt != nil && !fix.FixedAt.AsTime().IsZero() {
				lastFixed = fix.FixedAt.AsTime().Format("2006-01-02")
			}
			introduced := "N/A"
			if fix.IntroducedAt != nil && !fix.IntroducedAt.AsTime().IsZero() {
				introduced = fix.IntroducedAt.AsTime().Format("2006-01-02")
			}
			tbl.AddRow(
				workload.WorkloadName,
				workload.WorkloadNamespace,
				fix.Severity.String(),
				introduced,
				lastFixed,
				strconv.FormatBool(fix.FixedAt != nil && !fix.FixedAt.AsTime().IsZero()),
				fmt.Sprintf("%v", fix.MeanTimeToFixDays),
				fmt.Sprint(fix.FixedCount),
				fix.SnapshotDate.AsTime().Format("2006-01-02"),
			)
		}
	}

	tbl.Print()
	return nil
}

func listMeanTimeToFixTrendBySeverity(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, opts *flag.Options) error {
	resp, err := c.ListMeanTimeToFixTrendBySeverity(ctx, flag.ParseOptions(cmd, opts)...)
	if err != nil {
		return fmt.Errorf("failed to list mean time to fix per severity: %w", err)
	}

	tbl := output.New("Severity", "Snapshot Date", "Mean Time To Fix (days)", "Fix Count", "Fixed At (first)", "Fixed At (last)", "Workload Count")

	for _, n := range resp.GetPoints() {
		snapshot, firstFixedAt, lastFixedAt := "N/A", "N/A", "N/A"
		if n.SnapshotDate != nil && !n.SnapshotDate.AsTime().IsZero() {
			snapshot = n.SnapshotDate.AsTime().Format("2006-01-02")
		}
		if n.FirstFixedAt != nil && !n.FirstFixedAt.AsTime().IsZero() {
			firstFixedAt = n.FirstFixedAt.AsTime().Format("2006-01-02")
		}
		if n.LastFixedAt != nil && !n.LastFixedAt.AsTime().IsZero() {
			lastFixedAt = n.LastFixedAt.AsTime().Format("2006-01-02")
		}
		tbl.AddRow(
			n.Severity.String(),
			snapshot,
			fmt.Sprintf("%v", n.MeanTimeToFixDays),
			fmt.Sprint(n.FixedCount),
			firstFixedAt,
			lastFixedAt,
			fmt.Sprint(n.WorkloadCount),
		)
	}

	tbl.Print()
	return nil
}
