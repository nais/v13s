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
			Usage:   "trigger a sync command",
			Commands: []*cli.Command{
				{
					Name:    "update",
					Aliases: []string{"s"},
					Usage:   "trigger sync of images",
					Flags: append(flag.CommonFlags(opts, "limit", "order", "since"),
						&cli.StringFlag{
							Name:        "image-state",
							Aliases:     []string{"i"},
							Usage:       "filter by image state",
							Destination: &opts.ImageState,
						}),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						err := trigger(ctx, opts, c)
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
			Flags: append(flag.CommonFlags(opts, "order", "since"), &cli.BoolFlag{
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
		{
			Name:    "suppress",
			Aliases: []string{"sp"},
			Usage:   "suppress a vulnerability for a workload",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        "package",
					Aliases:     []string{"pkg"},
					Value:       "",
					Usage:       "package name to identify the vulnerability",
					Destination: &opts.Package,
				},
				&cli.StringFlag{
					Name:        "cve-id",
					Aliases:     []string{"cve"},
					Value:       "",
					Usage:       "CVE ID to identify the vulnerability",
					Destination: &opts.CveId,
				},
			},
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return suppressVulnerability(ctx, cmd, opts, c)
			},
		},
		{
			Name:  "workload",
			Usage: "workload related commands",
			Commands: []*cli.Command{
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "delete workload(s) and associated resources if not used by other workloads",
					Flags:   append(flag.CommonFlags(opts, "l", "o", "s", "su", "se")),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return deleteWorkload(ctx, opts, c)
					},
				},
			},
		},
	}
}

func deleteWorkload(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	var cluster, namespace, workload, workloadType = extractFilters(opts)
	if workload == nil || namespace == nil || cluster == nil {
		return fmt.Errorf("cluster, namespace, and workload must be provided to delete a workload")
	}

	_, err := c.DeleteWorkload(ctx, &management.DeleteWorkloadRequest{
		Cluster:      *cluster,
		Namespace:    *namespace,
		Workload:     *workload,
		WorkloadType: workloadType,
	})
	if err != nil {
		return err
	}
	fmt.Printf("workload %s/%s/%s deleted successfully\n", *cluster, *namespace, *workload)
	return nil
}

func suppressVulnerability(ctx context.Context, cmd *cli.Command, opts *flag.Options, c vulnerabilities.Client) error {
	imageName := ""
	imageTag := ""
	if cmd.Args().Len() <= 0 {
		return fmt.Errorf("image must be provided as the first argument in the format 'name:tag'")
	}

	arg := cmd.Args().First()
	if strings.Contains(arg, ":") && strings.Contains(arg, "/") {
		parts := strings.Split(arg, ":")
		imageName = parts[0]
		imageTag = parts[1]
	} else {
		return fmt.Errorf("invalid image format, expected 'name:tag'")
	}

	if opts.Package == "" || opts.CveId == "" {
		return fmt.Errorf("both package and cve-id must be provided to identify the vulnerability")
	}

	vuln, err := c.GetVulnerability(ctx, imageName, imageTag, opts.Package, opts.CveId)
	if err != nil {
		return fmt.Errorf("failed to get vulnerability: %w", err)
	}

	err = c.SuppressVulnerability(
		ctx,
		vuln.Vulnerability.Id,
		"Suppressing via CLI",
		"cli-user",
		vulnerabilities.SuppressState_FALSE_POSITIVE,
		true,
	)
	if err != nil {
		return fmt.Errorf("failed to suppress vulnerability: %w", err)
	}

	fmt.Printf("Vulnerability %s suppressed successfully\n", vuln.Vulnerability.Id)
	return nil
}

func trigger(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	var cluster, namespace, workload, workloadType = extractFilters(opts)
	var imageState *string
	if opts.ImageState != "" {
		imageState = &opts.ImageState
	}
	resp, err := c.Resync(ctx, &management.ResyncRequest{
		Cluster:      cluster,
		Namespace:    namespace,
		Workload:     workload,
		WorkloadType: workloadType,
		ImageState:   imageState,
	})
	if err != nil {
		return fmt.Errorf("failed to trigger sync: %w", err)
	}

	var headers []any
	var row []string

	headers = append(headers, "Updated Workloads", "Success")
	row = append(row, strconv.Itoa(len(resp.Workloads)), strconv.FormatBool(len(resp.Workloads) > 0))

	t := Table{
		Headers: headers,
	}
	t.AddRow(row...)
	t.Print()
	return nil
}

func getStatus(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	var cluster, namespace, workload, workloadType = extractFilters(opts)

	if opts.Limit <= 0 {
		opts.Limit = 30
	}

	err := pagination.Paginate(opts.Limit, func(offset int) (int, bool, error) {
		status, err := c.GetWorkloadStatus(ctx, &management.GetWorkloadStatusRequest{
			Cluster:      cluster,
			Namespace:    namespace,
			Workload:     workload,
			WorkloadType: workloadType,
			Limit:        int32(opts.Limit),
			Offset:       int32(offset),
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
	var cluster, namespace, workload, _ = extractFilters(opts)

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

func extractFilters(opts *flag.Options) (cluster, namespace, workload, workloadType *string) {
	if opts.Cluster != "" {
		cluster = &opts.Cluster
	}
	if opts.Namespace != "" {
		namespace = &opts.Namespace
	}
	if opts.Workload != "" {
		workload = &opts.Workload
	}
	if opts.WorkloadType != "" {
		workloadType = &opts.WorkloadType
	}
	return
}
