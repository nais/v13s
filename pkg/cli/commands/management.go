package commands

import (
	"context"
	"encoding/json"
	"fmt"
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
					Name:    "sync",
					Aliases: []string{"s"},
					Usage:   "trigger sync of images",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						_, err := c.TriggerSync(ctx, &management.TriggerSyncRequest{})
						return err
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
				var cluster, namespace, workload *string
				if opts.Cluster != "" {
					cluster = &opts.Cluster
				}
				if opts.Namespace != "" {
					namespace = &opts.Namespace
				}
				if opts.Workload != "" {
					workload = &opts.Workload
				}

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
					headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
					columnFmt := color.New(color.FgYellow).SprintfFunc()

					if opts.ShowJobs {
						tbl := table.New("Workload", "Id", "Kind", "State", "Metadata", "Attempts", "Errors", "Finished at")
						tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

						for _, s := range status.WorkloadStatus {
							for _, job := range s.Jobs {
								tbl.AddRow(
									s.Workload,
									job.Id,
									job.Kind,
									job.State,
									job.Metadata,
									job.Attempts,
									job.Errors,
									job.FinishedAt.AsTime().Format(time.RFC3339),
								)
							}
						}
						tbl.Print()
					} else {

						tbl := table.New("Workload", "Type", "Namespace", "Cluster", "State", "Image", "Image Tag", "Image State")
						tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

						for _, s := range status.WorkloadStatus {
							tbl.AddRow(
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
						tbl.Print()
					}
					return int(status.TotalCount), status.HasNextPage, nil
				})
				if err != nil {
					return err
				}
				return nil
			},
		},
		{
			Name:    "sbom",
			Aliases: []string{"s"},
			Usage:   "download sbom",
			Action: func(ctx context.Context, cmd *cli.Command) error {
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
			},
		},
	}
}
