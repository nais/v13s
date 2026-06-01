package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/output"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

func ManagementCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	return []*cli.Command{
		{
			Name:    "trigger",
			Aliases: []string{"t"},
			Usage:   "trigger management operations",
			Commands: []*cli.Command{
				{
					Name:    "sync",
					Aliases: []string{"s"},
					Usage:   "trigger image re-sync",
					Flags: append(
						flag.CommonFlags(opts, "limit", "order", "since", "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
						&cli.StringFlag{
							Name:        "image-state",
							Aliases:     []string{"i"},
							Usage:       "filter by image state",
							Destination: &opts.ImageState,
						},
						&cli.StringFlag{
							Name:        "workload-state",
							Aliases:     []string{"ws"},
							Usage:       "filter by workload state (e.g. no_attestation, updated, failed)",
							Destination: &opts.WorkloadState,
						},
					),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						if err := triggerSync(ctx, opts, c); err != nil {
							return fmt.Errorf("failed to trigger sync: %w", err)
						}
						return nil
					},
				},
			},
		},
		{
			Name:  "sbom",
			Usage: "SBOM commands",
			Commands: []*cli.Command{
				{
					Name:    "download",
					Aliases: []string{"d"},
					Usage:   "download the SBOM for an image",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:        "output",
							Aliases:     []string{"o"},
							Usage:       "output format (json, raw)",
							Destination: &opts.Output,
						},
					},
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return downloadSbom(ctx, cmd, opts)
					},
				},
			},
		},
		{
			Name:  "workload",
			Usage: "workload management",
			Commands: []*cli.Command{
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "delete a workload and its associated data",
					Flags:   flag.CommonFlags(opts, "limit", "order", "since", "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return deleteWorkload(ctx, opts, c)
					},
				},
			},
		},
	}
}

func deleteWorkload(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	cluster, namespace, workload, workloadType := extractFilters(opts)
	if workload == nil || namespace == nil || cluster == nil {
		return fmt.Errorf("--cluster, --namespace, and --workload must be provided")
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

func triggerSync(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	cluster, namespace, workload, workloadType := extractFilters(opts)
	var imageState *string
	if opts.ImageState != "" {
		imageState = &opts.ImageState
	}
	var workloadState *string
	if opts.WorkloadState != "" {
		workloadState = &opts.WorkloadState
	}
	resp, err := c.Resync(ctx, &management.ResyncRequest{
		Cluster:       cluster,
		Namespace:     namespace,
		Workload:      workload,
		WorkloadType:  workloadType,
		ImageState:    imageState,
		WorkloadState: workloadState,
	})
	if err != nil {
		return fmt.Errorf("failed to trigger sync: %w", err)
	}

	tbl := output.New("Updated Workloads", "Success")
	tbl.AddRow(strconv.Itoa(len(resp.Workloads)), strconv.FormatBool(len(resp.Workloads) > 0))
	tbl.Print()
	return nil
}

func downloadSbom(ctx context.Context, cmd *cli.Command, opts *flag.Options) error {
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

	out, err := json.MarshalIndent(att.Predicate, "", "  ")
	if err != nil {
		return err
	}

	if opts.Output == "json" {
		sbomBytes, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(out), `"`, ""))
		if err != nil {
			return fmt.Errorf("failed to decode sbom: %w", err)
		}
		fmt.Println(string(sbomBytes))
		return nil
	}

	fmt.Println(string(out))
	return nil
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
