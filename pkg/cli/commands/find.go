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

func FindCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	return []*cli.Command{
		{
			Name:    "find",
			Aliases: []string{"f"},
			Usage:   "find workloads and vulnerabilities",
			Commands: []*cli.Command{
				{
					Name:  "workloads",
					Usage: "list workloads matching filter",
					Flags: append(flag.CommonFlags(opts)),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return listWorkloads(ctx, cmd, c, opts)
					},
				},
				{
					Name:  "cve",
					Usage: "find cve matching id",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						if cmd.Args().First() == "" {
							return fmt.Errorf("cve id is required argument")
						}

						resp, err := c.GetCve(ctx, cmd.Args().First())
						if err != nil {
							return err
						}

						fmt.Printf(
							"CVE ID: %s\n\nDescription: %s\n\nSeverity: %s\n\nCvss Score: %v\n",
							resp.Cve.GetId(),
							resp.Cve.GetDescription(),
							resp.Cve.GetSeverity(),
							resp.Cve.GetCvssScore(),
						)
						return nil
					},
				},
			},
		},
	}
}

func listWorkloads(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *flag.Options) error {
	return pagination.Paginate(o.Limit, func(offset int) (int, bool, error) {
		opts := flag.ParseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(int32(offset)))

		vulnFilter := vulnerabilities.VulnerabilityFilter{}
		var cveIds []string
		if o.CveIds != "" {
			parts := strings.Split(o.CveIds, ",")
			for _, p := range parts {
				cveIds = append(cveIds, strings.TrimSpace(p))
			}
			vulnFilter.CveIds = cveIds
		}

		if o.CvssScore > 0 {
			vulnFilter.CvssScore = &o.CvssScore
		}

		resp, err := c.ListWorkloadsForVulnerability(ctx, vulnFilter, opts...)
		if err != nil {
			return 0, false, err
		}

		headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
		columnFmt := color.New(color.FgYellow).SprintfFunc()

		// Print vulnerabilities table for this workload
		tbl := table.New("Workload", "Package", "CVE", "Severity", "CVSS Score", "Severity Since")
		tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

		for _, n := range resp.GetNodes() {
			w := fmt.Sprintf("%s/%s/%s", n.GetWorkloadRef().GetCluster(), n.GetWorkloadRef().GetNamespace(), n.GetWorkloadRef().GetName())
			v := n.Vulnerability

			tbl.AddRow(
				w,
				v.GetPackage(),
				v.GetCve().GetId(),
				v.GetCve().GetSeverity(),
				v.GetCvssScore(),
				timeSinceCreation(v.SeveritySince.AsTime(), time.Now()),
			)
		}

		tbl.Print()

		return int(resp.PageInfo.TotalCount), resp.PageInfo.HasNextPage, nil
	})
}
