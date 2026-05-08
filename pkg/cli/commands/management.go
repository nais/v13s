package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/helpers"
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
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        "output",
					Aliases:     []string{"o"},
					Value:       "",
					Usage:       "output format (json, raw)",
					Destination: &opts.Output,
				},
			},
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return downloadSbom(ctx, cmd, opts)
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
			Name:    "suppress-all",
			Aliases: []string{"spa"},
			Usage:   "suppress a CVE across multiple workloads",
			Flags: append(flag.CommonFlags(opts, "limit", "order", "since", "since-type", "suppressed", "severity", "cve_ids", "cvss_score", "exclude-clusters", "exclude-namespaces"),
				&cli.StringFlag{
					Name:        "cve-id",
					Aliases:     []string{"cve"},
					Value:       "",
					Usage:       "CVE ID to suppress (required)",
					Destination: &opts.CveId,
				},
			),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				return suppressVulnerabilities(ctx, opts, c)
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
					Flags:   flag.CommonFlags(opts, "l", "o", "s", "su", "se"),
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
		return fmt.Errorf("both package and cve-id must be provided to identify the vulnerability" +
			"package in the format 'pkg:<package_name>@<version>' and cve-id in the format 'CVE-YYYY-NNNN'")
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
	cluster, namespace, workload, workloadType := extractFilters(opts)
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
	cluster, namespace, workload, workloadType := extractFilters(opts)

	if opts.Limit <= 0 {
		opts.Limit = 30
	}

	err := pagination.Paginate(opts.Limit, func(offset int) (int, bool, error) {
		status, err := c.GetWorkloadStatus(ctx, &management.GetWorkloadStatusRequest{
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
	cluster, namespace, workload, _ := extractFilters(opts)

	err := pagination.Paginate(opts.Limit, func(offset int) (int, bool, error) {
		status, err := c.GetWorkloadJobs(ctx, &management.GetWorkloadJobsRequest{
			Cluster:   cluster,
			Namespace: namespace,
			Workload:  workload,
			Limit:     helpers.MustIntToInt32(opts.Limit),
			Offset:    helpers.MustIntToInt32(offset),
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

func suppressVulnerabilities(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
	if opts.CveId == "" {
		return fmt.Errorf("--cve-id is required")
	}
	if opts.Cluster == "" {
		return fmt.Errorf("--cluster is required")
	}
	if opts.Namespace == "" {
		return fmt.Errorf("--namespace is required")
	}

	baseOpts := []vulnerabilities.Option{
		vulnerabilities.ClusterFilter(opts.Cluster),
		vulnerabilities.NamespaceFilter(opts.Namespace),
	}
	if opts.Workload != "" {
		baseOpts = append(baseOpts, vulnerabilities.WorkloadFilter(opts.Workload))
	}
	if opts.WorkloadType != "" {
		baseOpts = append(baseOpts, vulnerabilities.WorkloadTypeFilter(opts.WorkloadType))
	}

	const pageSize = int32(100)
	filter := vulnerabilities.VulnerabilityFilter{CveIds: []string{opts.CveId}}
	var workloads []*vulnerabilities.SuppressVulnerabilitiesWorkload
	seenWorkload := make(map[string]struct{})
	imageToWorkloads := make(map[string][]string)
	workloadToImage := make(map[string]string)
	workloadLabelToKey := make(map[string]string)
	var offset int32

	for {
		pageOpts := append(baseOpts, vulnerabilities.Limit(pageSize), vulnerabilities.Offset(offset))
		resp, err := c.ListWorkloadsForVulnerability(ctx, filter, pageOpts...)
		if err != nil {
			return fmt.Errorf("list workloads for vulnerability: %w", err)
		}
		for _, w := range resp.GetNodes() {
			ref := w.GetWorkloadRef()
			workloadKey := fmt.Sprintf("%s/%s/%s/%s", ref.GetCluster(), ref.GetNamespace(), ref.GetName(), ref.GetType())
			imageKey := fmt.Sprintf("%s:%s", ref.GetImageName(), ref.GetImageTag())
			workloadLabel := fmt.Sprintf("%s/%s/%s (%s)", ref.GetCluster(), ref.GetNamespace(), ref.GetName(), ref.GetType())
			if _, seen := seenWorkload[workloadKey]; !seen {
				imageToWorkloads[imageKey] = append(imageToWorkloads[imageKey], workloadLabel)
				workloadToImage[workloadKey] = imageKey
				workloadLabelToKey[workloadLabel] = workloadKey
				seenWorkload[workloadKey] = struct{}{}
				workloads = append(workloads, &vulnerabilities.SuppressVulnerabilitiesWorkload{
					Cluster:      ref.GetCluster(),
					Namespace:    ref.GetNamespace(),
					Name:         ref.GetName(),
					WorkloadType: ref.GetType(),
				})
			}
		}
		if !resp.GetPageInfo().GetHasNextPage() {
			break
		}
		offset += pageSize
	}

	if len(workloads) == 0 {
		fmt.Printf("no unsuppressed workloads found for %s — already suppressed or CVE not present in this namespace\n", opts.CveId)
		return nil
	}

	selected := workloads
	if len(workloads) > 1 {
		options := make([]huh.Option[*vulnerabilities.SuppressVulnerabilitiesWorkload], 0, len(workloads))
		for _, w := range workloads {
			label := fmt.Sprintf("%s/%s/%s (%s)", w.GetCluster(), w.GetNamespace(), w.GetName(), w.GetWorkloadType())
			options = append(options, huh.NewOption(label, w))
		}
		selected = nil
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewMultiSelect[*vulnerabilities.SuppressVulnerabilitiesWorkload]().
					Title(fmt.Sprintf("Select workloads to suppress %s", opts.CveId)).
					Description("Space to toggle, enter to confirm").
					Options(options...).
					Value(&selected),
			),
		)
		if err := form.Run(); err != nil {
			return fmt.Errorf("selection cancelled: %w", err)
		}
		if len(selected) == 0 {
			fmt.Println("no workloads selected, nothing suppressed")
			return nil
		}
	}

	sharedWarning := color.New(color.FgYellow).SprintfFunc()
	selectedKeys := make(map[string]struct{}, len(selected))
	for _, w := range selected {
		selectedKeys[fmt.Sprintf("%s/%s/%s/%s", w.GetCluster(), w.GetNamespace(), w.GetName(), w.GetWorkloadType())] = struct{}{}
	}
	warnedSiblings := make(map[string]struct{})
	for _, w := range selected {
		wKey := fmt.Sprintf("%s/%s/%s/%s", w.GetCluster(), w.GetNamespace(), w.GetName(), w.GetWorkloadType())
		img := workloadToImage[wKey]
		for _, siblingLabel := range imageToWorkloads[img] {
			siblingKey := workloadLabelToKey[siblingLabel]
			warnKey := siblingKey + "|" + img
			if _, ok := selectedKeys[siblingKey]; !ok {
				if _, warned := warnedSiblings[warnKey]; !warned {
					warnedSiblings[warnKey] = struct{}{}
					fmt.Println(sharedWarning("! suppressing %s will also affect %s (shared image %s)", w.GetName(), siblingLabel, img))
				}
			}
		}
	}

	result, err := c.SuppressVulnerabilities(
		ctx,
		opts.CveId,
		selected,
		vulnerabilities.SuppressState_FALSE_POSITIVE,
		"Suppressing via CLI",
		"cli-user",
		true,
	)
	if err != nil {
		return fmt.Errorf("suppress vulnerabilities (partial failures may have occurred): %w", err)
	}

	fmt.Printf("%s suppressed for %d workload(s) (%d unique image(s))\n",
		result.GetCveId(), result.GetWorkloadCount(), result.GetImageCount())
	return nil
}
