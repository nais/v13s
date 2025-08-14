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

	tbl := table.New("Package", "CVE", "Title", "Severity")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, n := range resp.GetNodes() {
		tbl.AddRow(
			n.GetPackage(),
			n.Cve.Id,
			n.Cve.Title,
			n.Cve.Severity,
		)
	}

	tbl.Print()
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
	err := pagination.Paginate(o.Limit, func(offset int) (int, bool, error) {
		opts := flag.ParseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(int32(offset)))
		resp, err := c.ListVulnerabilities(ctx, opts...)
		if err != nil {
			return 0, false, fmt.Errorf("failed to list vulnerabilities: %w", err)
		}

		headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
		columnFmt := color.New(color.FgYellow).SprintfFunc()

		tbl := table.New("Package", "CVE", "Severity", "Image", "Workload", "Type", "Namespace", "Cluster")
		tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

		for _, n := range resp.GetNodes() {
			v := n.Vulnerability
			w := n.WorkloadRef
			parts := strings.Split(w.ImageName, "/")
			image := fmt.Sprintf(".../%s:%s", parts[len(parts)-1], w.ImageTag)
			tbl.AddRow(
				v.GetPackage(),
				v.GetCve().GetId(),
				v.GetCve().GetSeverity(),
				image,
				w.Name,
				w.Type,
				w.Namespace,
				w.Cluster,
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
