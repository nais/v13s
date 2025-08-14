package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/pagination"
	"github.com/rodaine/table"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

func ManagementCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	return []*cli.Command{
		{
			Name:    "trigger",
			Aliases: []string{"t"},
			Usage:   "trigger a sync command",
			Commands: []*cli.Command{
				{
					Name:    "update",
					Aliases: []string{"s"},
					Usage:   "trigger sync of images",
					Flags:   append(flag.CommonFlags(opts, "limit", "order", "since")),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						err := trigger(ctx, c, opts)
						if err != nil {
							return fmt.Errorf("failed to trigger update: %w", err)
						}
						return nil
					},
				},
			},
		},
		{
			Name:    "status",
			Aliases: []string{"st"},
			Usage:   "get workload status",
			Flags: append(flag.CommonFlags(opts, "limit", "order", "since"), &cli.BoolFlag{
				Name:        "show-jobs",
				Aliases:     []string{"j"},
				Usage:       "show jobs associated with the workload",
				Destination: &opts.ShowJobs,
			}),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				err := getStatus(ctx, opts, c)
				if err != nil {
					return fmt.Errorf("failed to get workload status: %w", err)
				}
				if opts.ShowJobs {
					err = getWorkloadJobStatus(ctx, opts, c)
					if err != nil {
						return fmt.Errorf("failed to get workload job status: %w", err)
					}
				}
				return nil
			},
		},
		{
			Name:    "sbom",
			Aliases: []string{"s"},
			Usage:   "download sbom",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return downloadSbom(ctx, cmd)
			},
		},
	}
}

func trigger(ctx context.Context, c vulnerabilities.Client, opts *flag.Options) error {
	resp, err := c.TriggerSync(ctx, &management.TriggerSyncRequest{
		Cluster:      opts.Cluster,
		Namespace:    opts.Namespace,
		Workload:     opts.Workload,
		WorkloadType: opts.WorkloadType,
	})
	if err != nil {
		return fmt.Errorf("failed to trigger sync: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf(
			"sync failed for cluster: %s, namespace: %s, workload: %s",
			parseString(opts.Cluster),
			parseString(opts.Namespace),
			parseString(opts.Workload),
		)
	}

	var headers []any
	var row []string

	if resp.Cluster != "" {
		headers = append(headers, "Cluster")
		row = append(row, resp.Cluster)
	}
	if resp.Namespace != "" {
		headers = append(headers, "Namespace")
		row = append(row, resp.Namespace)
	}
	if resp.Workload != "" {
		headers = append(headers, "Workload")
		row = append(row, resp.Workload)
	}

	headers = append(headers, "Updated Workloads", "Success")
	row = append(row, strconv.Itoa(len(resp.UpdatedWorkloads)), strconv.FormatBool(resp.Success))

	t := Table{
		Headers: headers,
	}
	t.AddRow(row...)
	t.Print()
	return nil
}

func parseString(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}

func getStatus(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	var cluster, namespace, workload = extractFilters(opts)

	err := pagination.Paginate(opts.Limit, func(offset int) (int, bool, error) {
		status, err := c.GetWorkloadStatus(ctx, &management.GetWorkloadStatusRequest{
			Cluster:   cluster,
			Namespace: namespace,
			Workload:  workload,
			Limit:     int32(opts.Limit),
			Offset:    int32(offset),
		})
		if err != nil {
			return 0, false, fmt.Errorf("failed to get workload status: %w", err)
		}

		t := Table{
			Headers: []any{"Workload", "Type", "Namespace", "Cluster", "State", "Image Name", "Image Tag", "Image State"},
		}

		for _, s := range status.WorkloadStatus {
			t.AddRow(
				s.Workload,
				s.WorkloadType,
				s.Namespace,
				s.Cluster,
				s.WorkloadState,
				s.ImageName,
				s.ImageTag,
				s.ImageState,
			)
		}
		t.Print()
		return int(status.TotalCount), status.HasNextPage, nil
	})
	if err != nil {
		return err
	}

	return nil
}

func getWorkloadJobStatus(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	var cluster, namespace, workload = extractFilters(opts)

	err := pagination.Paginate(opts.Limit, func(offset int) (int, bool, error) {
		status, err := c.GetWorkloadJobs(ctx, &management.GetWorkloadJobsRequest{
			Cluster:   cluster,
			Namespace: namespace,
			Workload:  workload,
			Limit:     int32(opts.Limit),
			Offset:    int32(offset),
		})
		if err != nil {
			return 0, false, fmt.Errorf("failed to get workload jobs: %w", err)
		}

		t := Table{
			Headers: []any{"Job ID", "Kind", "State", "Metadata", "Attempts", "Errors", "Finished At"},
		}

		for _, job := range status.GetJobs() {
			t.AddRow(
				strconv.FormatInt(job.Id, 10),
				job.Kind,
				job.State,
				job.Metadata,
				strconv.Itoa(int(job.Attempts)),
				job.Errors,
				job.FinishedAt.AsTime().Format(time.RFC3339),
			)
		}
		t.Print()
		return int(status.TotalCount), status.HasNextPage, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func downloadSbom(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() == 0 {
		return fmt.Errorf("missing image")
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
	out, err := json.MarshalIndent(att.Statement.Predicate, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

type Table struct {
	Headers []any
	Rows    [][]string
}

func (t *Table) AddRow(row ...string) {
	t.Rows = append(t.Rows, row)
}

func (t *Table) Print() {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()
	tbl := table.New(t.Headers...)
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	tbl.SetRows(t.Rows)
	tbl.Print()
}

func extractFilters(opts *flag.Options) (cluster, namespace, workload *string) {
	if opts.Cluster != "" {
		cluster = &opts.Cluster
	}
	if opts.Namespace != "" {
		namespace = &opts.Namespace
	}
	if opts.Workload != "" {
		workload = &opts.Workload
	}
	return
}
