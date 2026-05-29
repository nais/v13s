package commands

import (
	"context"
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/nais/v13s/pkg/cli/helpers"
	"github.com/urfave/cli/v3"
)

func SuppressCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	return []*cli.Command{
		{
			Name:    "suppress",
			Aliases: []string{"sp"},
			Usage:   "suppress vulnerabilities",
			Commands: []*cli.Command{
				{
					Name:    "one",
					Aliases: []string{"o"},
					Usage:   "suppress a single vulnerability for an image (format: <image>:<tag>)",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:        "package",
							Aliases:     []string{"pkg"},
							Usage:       "package name to identify the vulnerability",
							Destination: &opts.Package,
						},
						&cli.StringFlag{
							Name:        "cve-id",
							Aliases:     []string{"cve"},
							Usage:       "CVE ID to identify the vulnerability",
							Destination: &opts.CveId,
						},
					},
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return suppressOne(ctx, cmd, opts, c)
					},
				},
				{
					Name:    "all",
					Aliases: []string{"a"},
					Usage:   "suppress a CVE across multiple workloads",
					Flags: append(
						flag.CommonFlags(opts, "limit", "order", "since", "since-type", "suppressed", "severity", "cve-ids", "cvss-score", "exclude-clusters", "exclude-namespaces"),
						&cli.StringFlag{
							Name:        "cve-id",
							Aliases:     []string{"cve"},
							Usage:       "CVE ID to suppress (required)",
							Destination: &opts.CveId,
						},
					),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return suppressAll(ctx, opts, c)
					},
				},
			},
		},
	}
}

func suppressOne(ctx context.Context, cmd *cli.Command, opts *flag.Options, c vulnerabilities.Client) error {
	if cmd.Args().Len() <= 0 {
		return fmt.Errorf("image must be provided as the first argument in the format 'name:tag'")
	}

	imageName, imageTag, err := helpers.SplitImageRef(cmd.Args().First())
	if err != nil {
		return err
	}

	if opts.Package == "" || opts.CveId == "" {
		return fmt.Errorf("both --package and --cve-id must be provided")
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

func suppressAll(ctx context.Context, opts *flag.Options, c vulnerabilities.Client) error {
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
