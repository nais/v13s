package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/pagination"
	"github.com/rodaine/table"
	"github.com/urfave/cli/v3"
)

func ListCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	return []*cli.Command{
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "list vulnerabilities",
			Commands: []*cli.Command{
				{
					Name:    "image",
					Aliases: []string{"v"},
					Usage:   "list vulnerabilities for image",
					Flags:   flag.CommonFlags(opts, "cluster", "namespace", "workload"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listVulnerabilitiesForImage(ctx, cmd, c, opts)
					},
				},
				{
					Name:  "suppressed",
					Usage: "list suppressed vulnerabilities",
					Flags: flag.CommonFlags(opts),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listSuppressedVulnerabilities(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "all",
					Aliases: []string{"a"},
					Usage:   "list all vulnerabilities with optional filters",
					Flags:   flag.CommonFlags(opts),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listVulnz(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "summary",
					Aliases: []string{"s"},
					Usage:   "list vulnerability summary for filter",
					Flags:   flag.CommonFlags(opts),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listSummaries(ctx, cmd, c, opts)
					},
				},
				{
					Name:  "mttf",
					Usage: "list mean time to fix (MTTF) for workload severities",
					Flags: flag.CommonFlags(opts, "l", "o", "su"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listWorkloadMTTFBySeverity(ctx, cmd, c, opts)
					},
				},
				{
					Name:  "mttf-trend",
					Usage: "list mean time to fix (MTTF) per severity trend",
					Flags: flag.CommonFlags(opts, "l", "o", "su"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listMeanTimeToFixTrendBySeverity(ctx, cmd, c, opts)
					},
				},
			},
		},
	}
}

func listVulnerabilitiesForImage(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	opts := flag.ParseOptions(cmd, o)
	if cmd.Args().Len() == 0 {
		return fmt.Errorf("missing image name")
	}
	parts := strings.Split(cmd.Args().First(), ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid image format: %s, expected format: <image>:<tag>", cmd.Args().First())
	}
	start := time.Now()
	resp, err := c.ListVulnerabilitiesForImage(ctx, parts[0], parts[1], opts...)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	vulnTbl := table.New("Package", "CVE", "Title", "Severity", "Severity Since", "Created", "Last Updated", "Suppressed")
	vulnTbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	var suppressions [][]string

	for _, n := range resp.GetNodes() {
		suppressed := "No"
		if n.GetSuppression() != nil && n.GetSuppression().GetSuppressed() {
			suppressed = "Yes"
		}
		vulnTbl.AddRow(
			n.GetPackage(),
			n.Cve.Id,
			n.Cve.Title,
			n.Cve.Severity,
			n.SeveritySince.AsTime().Format(time.RFC3339),
			n.GetCreated().AsTime().Format(time.RFC3339),
			n.GetLastUpdated().AsTime().Format(time.RFC3339),
			suppressed,
		)

		// Only add to suppression table if suppressed
		if n.GetSuppression() != nil && n.GetSuppression().GetSuppressed() {
			suppressions = append(suppressions, []string{
				n.Cve.Id,
				n.GetPackage(),
				n.GetLatestVersion(),
				n.GetSuppression().GetSuppressedReason().String(),
				n.GetSuppression().GetSuppressedBy(),
				n.GetSuppression().GetLastUpdated().AsTime().Format(time.RFC3339),
			})
		}
	}

	vulnTbl.Print()

	if len(suppressions) > 0 {
		fmt.Println("\nSuppressed vulnerabilities:")
		suppTbl := table.New("CVE", "Package", "Latest Version", "Reason", "Suppressed By", "Suppressed At")
		suppTbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
		for _, row := range suppressions {
			// Convert []string to []interface{}
			rowInterface := make([]interface{}, len(row))
			for i, v := range row {
				rowInterface[i] = v
			}
			suppTbl.AddRow(rowInterface...)
		}
		suppTbl.Print()
	}

	fmt.Println("\nFetched vulnerabilities in", time.Since(start).Seconds(), "seconds")
	return nil
}

func listSuppressedVulnerabilities(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	opts := flag.ParseOptions(cmd, o)
	start := time.Now()
	resp, err := c.ListSuppressedVulnerabilities(ctx, opts...)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Package", "CVE", "Reason", "Suppressed", "Suppressed By", "Image")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, n := range resp.GetNodes() {
		tbl.AddRow(
			n.GetPackage(),
			n.CveId,
			*n.Reason,
			*n.Suppress,
			*n.SuppressedBy,
			n.ImageName,
		)
	}

	tbl.Print()
	fmt.Println("\nFetched vulnerabilities in", time.Since(start).Seconds(), "seconds")

	return nil
}

func listSummaries(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	err := pagination.Paginate(o.Limit, func(offset int) (int, bool, error) {
		opts := flag.ParseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(int32(offset)))
		resp, err := c.ListVulnerabilitySummaries(ctx, opts...)
		if err != nil {
			return 0, false, fmt.Errorf("failed to list vulnerability summaries: %w", err)
		}

		headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
		columnFmt := color.New(color.FgYellow).SprintfFunc()

		headers := []any{"Workload", "Type", "Cluster", "Namespace", "Has SBOM", "Critical", "High", "Medium", "Low", "Unassigned", "RiskScore"}
		if o.Since != "" {
			headers = append(headers, "ImageTag")
			headers = append(headers, "Last Updated")
		}
		tbl := table.New(headers...)
		tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

		for _, n := range resp.GetNodes() {
			vals := []any{
				// kills the layout
				// n.Workload.GetImageName()+":"+n.GetWorkload().GetImageTag(),
				n.Workload.GetName(),
				n.Workload.GetType(),
				n.Workload.GetCluster(),
				n.Workload.GetNamespace(),
				n.GetVulnerabilitySummary().GetHasSbom(),
				n.GetVulnerabilitySummary().GetCritical(),
				n.GetVulnerabilitySummary().GetHigh(),
				n.GetVulnerabilitySummary().GetMedium(),
				n.GetVulnerabilitySummary().GetLow(),
				n.GetVulnerabilitySummary().GetUnassigned(),
				n.GetVulnerabilitySummary().GetRiskScore(),
			}
			if o.Since != "" {
				vals = append(vals, n.Workload.GetImageTag())
				vals = append(vals, n.GetVulnerabilitySummary().GetLastUpdated().AsTime().Format(time.RFC3339))
			}
			tbl.AddRow(
				vals...,
			)
		}

		tbl.Print()

		return int(resp.PageInfo.TotalCount), resp.PageInfo.HasNextPage, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func listVulnz(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	return pagination.Paginate(o.Limit, func(offset int) (int, bool, error) {
		opts := flag.ParseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(int32(offset)))

		resp, err := c.ListVulnerabilities(ctx, opts...)
		if err != nil {
			return 0, false, fmt.Errorf("failed to list vulnerabilities: %w", err)
		}

		headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
		columnFmt := color.New(color.FgYellow).SprintfFunc()
		workloadHeader := color.New(color.FgGreen, color.Bold).SprintfFunc()
		workloadDetails := color.New(color.FgYellow).SprintfFunc()

		// Group vulnerabilities by workload
		workloadMap := make(map[string][]*vulnerabilities.Finding)
		for _, n := range resp.GetNodes() {
			w := n.WorkloadRef
			key := fmt.Sprintf("%s/%s/%s/%s", w.Name, w.Type, w.Namespace, w.Cluster)
			workloadMap[key] = append(workloadMap[key], n)
		}

		fmt.Println(workloadHeader("Total vulnerabilities found: %d", resp.PageInfo.TotalCount))
		fmt.Println(workloadDetails("Total workloads with vulnerabilities: %d", len(workloadMap)))

		for _, findings := range workloadMap {
			if len(findings) == 0 {
				continue
			}
			w := findings[0].WorkloadRef

			// Print workload details
			fmt.Println(workloadHeader("\nWorkload: %s", w.Name))
			fmt.Println(workloadDetails("Type: %s", w.Type))
			fmt.Println(workloadDetails("Namespace: %s", w.Namespace))
			fmt.Println(workloadDetails("Cluster: %s", w.Cluster))
			fmt.Println(workloadDetails("Image: %s:%s", w.ImageName, w.ImageTag))

			// Print vulnerabilities table for this workload
			tbl := table.New("Package", "CVE", "Severity", "CVE Last Updated", "Last Severity", "Severity Sins", "Latest Version", "Suppressed", "Time Since Update")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			for _, n := range findings {
				v := n.Vulnerability
				suppressed := "No"
				if v.GetSuppression() != nil && v.GetSuppression().GetSuppressed() {
					suppressed = "Yes"
				}

				tbl.AddRow(
					v.GetPackage(),
					v.GetCve().GetId(),
					v.GetCve().GetSeverity(),
					timeSinceCreation(v.GetCve().GetCreated().AsTime(), v.GetCve().GetLastUpdated().AsTime()),
					v.GetLastSeverity(),
					timeSinceCreation(v.SeveritySince.AsTime(), time.Now()),
					v.GetLatestVersion(),
					suppressed,
					timeSinceCreation(v.GetCreated().AsTime(), v.GetLastUpdated().AsTime()),
				)
			}

			tbl.Print()
		}

		return int(resp.PageInfo.TotalCount), resp.PageInfo.HasNextPage, nil
	})
}

func listWorkloadMTTFBySeverity(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, opts *flag.Options) error {
	resp, err := c.ListWorkloadMTTFBySeverity(ctx, flag.ParseOptions(cmd, opts)...)
	if err != nil {
		return fmt.Errorf("failed to list workload severities with MTTF: %w", err)
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New(
		"Workload", "Cluster", "Namespace", "Severity", "Introduced At", "Fixed At", "Fixed", "Fix Duration (days)", "Fix Count", "Snapshot Date")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

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
				workload.WorkloadCluster,
				workload.WorkloadNamespace,
				fix.Severity.String(),
				introduced,
				lastFixed,
				fix.FixedAt != nil && !fix.FixedAt.AsTime().IsZero(),
				fix.MeanTimeToFixDays,
				fix.FixedCount,
				fix.SnapshotTime.AsTime().Format("2006-01-02"),
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

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New(
		"Severity", "Snapshot Date", "Mean Time To Fix (days)", "Fix Count", "First Fixed At", "Last Fixed At")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, n := range resp.GetNodes() {
		snapshot := "N/A"
		firstFixedAt := "N/A"
		lastFixedAt := "N/A"
		if n.SnapshotTime != nil && !n.SnapshotTime.AsTime().IsZero() {
			snapshot = n.SnapshotTime.AsTime().Format("2006-01-02")
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
			n.MeanTimeToFixDays,
			n.FixedCount,
			firstFixedAt,
			lastFixedAt,
		)
	}

	tbl.Print()
	return nil
}

func timeSinceCreation(created, lastUpdated time.Time) string {
	if lastUpdated.IsZero() || created.IsZero() {
		return "unknown"
	}

	duration := lastUpdated.Sub(created)

	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}
