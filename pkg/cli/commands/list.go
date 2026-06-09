package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/helpers"
	"github.com/nais/v13s/pkg/cli/output"
	"github.com/nais/v13s/pkg/cli/pagination"
	"github.com/urfave/cli/v3"
)

func ListCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	return []*cli.Command{
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "list vulnerabilities or summaries",
			Commands: []*cli.Command{
				{
					Name:    "vulns",
					Aliases: []string{"v"},
					Usage:   "list vulnerabilities for an image",
					Flags:   flag.CommonFlags(opts, "cluster", "namespace", "workload", "type", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listVulnerabilitiesForImage(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "all",
					Aliases: []string{"a"},
					Usage:   "list all vulnerabilities across workloads",
					Flags:   flag.CommonFlags(opts, "since", "since-type", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listVulnz(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "suppressed",
					Aliases: []string{"sp"},
					Usage:   "list suppressed vulnerabilities",
					Flags:   flag.CommonFlags(opts, "since", "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listSuppressedVulnerabilities(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "summary",
					Aliases: []string{"s"},
					Usage:   "list vulnerability summary per workload",
					Flags:   flag.CommonFlags(opts, "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listSummaries(ctx, cmd, c, opts)
					},
				},
				{
					Name:    "cves",
					Aliases: []string{"c"},
					Usage:   "list CVE summaries across workloads",
					Flags:   flag.CommonFlags(opts, "since", "since-type", "severity", "cve-ids", "cvss-score"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listCveSummaries(ctx, cmd, c, opts)
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
	imageName, imageTag, err := helpers.SplitImageRef(cmd.Args().First())
	if err != nil {
		return err
	}
	start := time.Now()
	resp, err := c.ListVulnerabilitiesForImage(ctx, imageName, imageTag, opts...)
	if err != nil {
		return err
	}

	tbl := output.New("Package", "CVE", "Title", "Severity", "Severity Since", "Created", "Last Updated", "Suppressed")

	var suppressions [][]string

	for _, n := range resp.GetNodes() {
		suppressed := "No"
		if n.GetSuppression() != nil && n.GetSuppression().GetSuppressed() {
			suppressed = "Yes"
		}
		tbl.AddRow(
			n.GetPackage(),
			n.Cve.Id,
			n.Cve.Title,
			n.Cve.Severity.String(),
			n.SeveritySince.AsTime().Format(time.RFC3339),
			n.GetCreated().AsTime().Format(time.RFC3339),
			n.GetLastUpdated().AsTime().Format(time.RFC3339),
			suppressed,
		)

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

	tbl.Print()

	if len(suppressions) > 0 {
		fmt.Println("\nSuppressed vulnerabilities:")
		suppTbl := output.New("CVE", "Package", "Latest Version", "Reason", "Suppressed By", "Suppressed At")
		for _, row := range suppressions {
			suppTbl.AddRow(row...)
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

	tbl := output.New("Package", "CVE", "Reason", "Suppressed", "Suppressed By", "Image")

	for _, n := range resp.GetNodes() {
		tbl.AddRow(
			n.GetPackage(),
			n.CveId,
			*n.Reason,
			fmt.Sprint(*n.Suppress),
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
		opts = append(opts, vulnerabilities.Offset(helpers.MustIntToInt32(offset)))
		resp, err := c.ListVulnerabilitySummaries(ctx, opts...)
		if err != nil {
			return 0, false, fmt.Errorf("failed to list vulnerability summaries: %w", err)
		}

		headers := []any{"Workload", "Type", "Cluster", "Namespace", "SBOM Status", "Risk Tier", "Act Now", "Critical", "High", "Medium", "Low", "Unassigned", "RiskScore"}
		if o.Since != "" {
			headers = append(headers, "ImageTag", "Last Updated")
		}

		tbl := output.New(headers...)

		for _, n := range resp.GetNodes() {
			sum := n.GetVulnerabilitySummary()
			hasSummary := sum != nil
			row := []string{
				n.Workload.GetName(),
				n.Workload.GetType(),
				n.Workload.GetCluster(),
				n.Workload.GetNamespace(),
				formatSbomStatus(n.GetSbomStatus()),
				formatRiskTier(sum, hasSummary),
				intOrDash(sum.GetActNow(), hasSummary),
				intOrDash(sum.GetCritical(), hasSummary),
				intOrDash(sum.GetHigh(), hasSummary),
				intOrDash(sum.GetMedium(), hasSummary),
				intOrDash(sum.GetLow(), hasSummary),
				intOrDash(sum.GetUnassigned(), hasSummary),
				intOrDash(sum.GetRiskScore(), hasSummary),
			}
			if o.Since != "" {
				lastUpdated := "-"
				if ts := sum.GetLastUpdated(); ts != nil {
					lastUpdated = ts.AsTime().Format(time.RFC3339)
				}
				row = append(row, n.Workload.GetImageTag(), lastUpdated)
			}
			tbl.AddRow(row...)
		}

		tbl.Print()

		return int(resp.PageInfo.TotalCount), resp.PageInfo.HasNextPage, nil
	})
	return err
}

func listVulnz(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	return pagination.Paginate(o.Limit, func(offset int) (int, bool, error) {
		opts := flag.ParseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(helpers.MustIntToInt32(offset)))

		resp, err := c.ListVulnerabilities(ctx, opts...)
		if err != nil {
			return 0, false, fmt.Errorf("failed to list vulnerabilities: %w", err)
		}

		workloadHeader := output.HeaderFmt
		workloadDetails := output.ColumnFmt

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

			fmt.Println(workloadHeader("\nWorkload: %s", w.Name))
			fmt.Println(workloadDetails("Type: %s", w.Type))
			fmt.Println(workloadDetails("Namespace: %s", w.Namespace))
			fmt.Println(workloadDetails("Cluster: %s", w.Cluster))
			fmt.Println(workloadDetails("Image: %s:%s", w.ImageName, w.ImageTag))

			tbl := output.New("Package", "CVE", "Severity", "CVSS Score", "CVE Age", "Last Severity", "Severity Since", "Latest Version", "Suppressed", "Vuln Age")

			for _, n := range findings {
				v := n.Vulnerability
				suppressed := "No"
				if v.GetSuppression() != nil && v.GetSuppression().GetSuppressed() {
					suppressed = "Yes"
				}

				tbl.AddRow(
					v.GetPackage(),
					v.GetCve().GetId(),
					v.GetCve().GetSeverity().String(),
					formatCvssScore(v.GetCve().GetCvssScore()),
					timeSinceCreation(v.GetCve().GetCreated().AsTime(), v.GetCve().GetLastUpdated().AsTime()),
					fmt.Sprintf("%v", v.GetLastSeverity()),
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

func listCveSummaries(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	return pagination.Paginate(o.Limit, func(offset int) (int, bool, error) {
		opts := flag.ParseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(helpers.MustIntToInt32(offset)))
		resp, err := c.ListCveSummaries(ctx, opts...)
		if err != nil {
			return 0, false, fmt.Errorf("failed to list CVE summaries: %w", err)
		}

		tbl := output.New("CVE", "Title", "Severity", "CVSS Score", "Affected Workloads")

		for _, n := range resp.GetNodes() {
			cve := n.GetCve()
			tbl.AddRow(
				cve.GetId(),
				cve.GetTitle(),
				cve.GetSeverity().String(),
				formatCvssScore(cve.GetCvssScore()),
				fmt.Sprint(n.GetAffectedWorkloads()),
			)
		}

		tbl.Print()

		return int(resp.PageInfo.TotalCount), resp.PageInfo.HasNextPage, nil
	})
}

func formatCvssScore(score float64) string {
	if score == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%g", score)
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

func intOrDash(v int32, hasSbom bool) string {
	if !hasSbom {
		return "-"
	}
	return fmt.Sprint(v)
}

func sbomStatusLabel(s *vulnerabilities.SbomStatusInfo) string {
	if s == nil {
		return "PROCESSING"
	}
	status := s.GetStatus()
	if status == vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED {
		return "PROCESSING"
	}
	return strings.TrimPrefix(status.String(), "SBOM_STATUS_")
}

func formatSbomStatus(s *vulnerabilities.SbomStatusInfo) string {
	label := sbomStatusLabel(s)
	if s == nil {
		return label
	}
	status := s.GetStatus()
	if status == vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING || status == vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED {
		if ts := s.GetProcessingStartedAt(); ts != nil {
			elapsed := time.Since(ts.AsTime()).Round(time.Second)
			return fmt.Sprintf("%s (%s)", label, elapsed)
		}
	}
	return label
}

func formatRiskTier(sum *vulnerabilities.Summary, hasSummary bool) string {
	if !hasSummary || sum == nil {
		return "-"
	}
	switch sum.GetTopRiskTier() {
	case vulnerabilities.RiskTier_ACT_NOW:
		return "ACT_NOW"
	case vulnerabilities.RiskTier_HIGH_RISK:
		return "HIGH_RISK"
	case vulnerabilities.RiskTier_ELEVATED_RISK:
		return "ELEVATED_RISK"
	case vulnerabilities.RiskTier_MONITOR:
		return "MONITOR"
	default:
		return "-"
	}
}
