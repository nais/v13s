package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
			Usage:   "trigger a command",
			Commands: []*cli.Command{
				{
					Name:    "update",
					Aliases: []string{"s"},
					Usage:   "trigger sync of images",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						_, err := c.TriggerSync(ctx, &management.TriggerSyncRequest{})
						return err
					},
				},
				{
					Name:    "resync",
					Aliases: []string{"r"},
					Usage:   "trigger resync of workloads",
					Flags: append(flag.CommonFlags(opts, "limit", "order", "since"), &cli.StringFlag{
						Name:    "workload-state",
						Aliases: []string{"ws"},
						Value:   "",
						Usage: "workload state, e.g. 'processing', 'initialized', 'updated', 'no_attestation', 'failed', 'unrecoverable', 'resync'" +
							"Default is resync.",
						Destination: &opts.WorkloadState,
					},
						&cli.StringFlag{
							Name:    "image-state",
							Aliases: []string{"is"},
							Value:   "",
							Usage: "image state, e.g. 'initialized', 'updated', 'untracked', 'failed', 'resync', 'outdated', 'unused'" +
								"Default is resync.",
							Destination: &opts.ImageState,
						}),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return resync(ctx, c, opts)
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

func resync(ctx context.Context, c vulnerabilities.Client, opts *flag.Options) error {
	// validate state
	if err := validateState(opts.WorkloadState); err != nil {
		return err
	}

	resp, err := c.Resync(ctx, &management.ResyncRequest{
		Cluster:       p(opts.Cluster),
		Namespace:     p(opts.Namespace),
		Workload:      p(opts.Workload),
		WorkloadType:  p(opts.WorkloadType),
		WorkloadState: p(opts.WorkloadState),
		ImageState:    p(opts.ImageState),
	})
	if err != nil {
		return fmt.Errorf("failed to trigger resync: %w", err)
	}

	t := Table{
		Headers: []any{"Cluster", "Namespace", "Type", "Workload"},
	}
	for _, w := range resp.Workloads {
		parts := strings.Split(w, "/")
		if len(parts) != 4 {
			log.Warnf("unexpected workload format: %s", w)
			continue
		}
		t.AddRow(parts...)
	}
	t.Print()
	return nil
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

func p(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func validateState(workloadState string) error {
	var validStates = []string{
		"processing", "initialized", "updated", "no_attestation",
		"failed", "unrecoverable", "resync",
	}
	validSet := make(map[string]struct{}, len(validStates))
	for _, s := range validStates {
		validSet[s] = struct{}{}
	}

	if workloadState != "" {
		if _, ok := validSet[workloadState]; !ok {
			return fmt.Errorf("invalid workload state: %q\nvalid states: %s",
				workloadState, strings.Join(validStates, ", "))
		}
	}
	return nil
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
