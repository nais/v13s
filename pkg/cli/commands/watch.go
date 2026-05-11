package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/flag"
	"github.com/rodaine/table"
	"github.com/urfave/cli/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultWatchInterval = 5 * time.Second

// watchWorkload identifies a workload to watch.
type watchWorkload struct {
	cluster   string
	namespace string
	name      string
	wtype     string
}

func (w watchWorkload) label() string {
	return fmt.Sprintf("%s / %s / %s (%s)", w.cluster, w.namespace, w.name, w.wtype)
}

func WatchCommands(c vulnerabilities.Client, opts *flag.Options) []*cli.Command {
	var intervalSec int
	return []*cli.Command{
		{
			Name:    "watch",
			Aliases: []string{"w"},
			Usage:   "watch SBOM processing status",
			Commands: []*cli.Command{
				{
					Name:  "sbom-status",
					Usage: "interactively pick a workload with pending SBOM and watch its status",
					Flags: append(
						flag.CommonFlags(opts, "l", "o", "s", "st", "su", "se", "cve_ids", "cvss_score", "excs", "exns"),
						&cli.IntFlag{
							Name:        "interval",
							Aliases:     []string{"i"},
							Value:       5,
							Usage:       "poll interval in seconds",
							Destination: &intervalSec,
						},
					),
					Action: func(ctx context.Context, cmd *cli.Command) error {
						return watchSbomStatus(ctx, c, opts, time.Duration(intervalSec)*time.Second)
					},
				},
			},
		},
	}
}

// watchSbomStatus fetches workloads with pending SBOM, lets the user pick one,
// then polls and clears the screen until cancelled.
func watchSbomStatus(ctx context.Context, c vulnerabilities.Client, o *flag.Options, interval time.Duration) error {
	if interval <= 0 {
		interval = defaultWatchInterval
	}

	// --- 1. Collect all workloads with a pending SBOM status ---
	pending, err := collectPendingWorkloads(ctx, c, o)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Println("No workloads with pending SBOM processing found.")
		return nil
	}

	// --- 2. Interactive picker ---
	selected, err := pickWorkload(pending)
	if err != nil {
		return err
	}

	// --- 3. Watch loop ---
	return runWatchLoop(ctx, c, selected, interval)
}

// collectPendingWorkloads pages through ListVulnerabilitySummaries and returns
// only workloads whose SBOM status is UNSPECIFIED (maps to PROCESSING) or
// SBOM_STATUS_PROCESSING.
func collectPendingWorkloads(ctx context.Context, c vulnerabilities.Client, o *flag.Options) ([]watchWorkload, error) {
	const pageSize = 100
	var out []watchWorkload
	offset := int32(0)

	baseOpts := buildBaseOpts(o)

	for {
		opts := append(baseOpts,
			vulnerabilities.Limit(pageSize),
			vulnerabilities.Offset(offset),
		)
		resp, err := c.ListVulnerabilitySummaries(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("listing workloads: %w", err)
		}

		for _, node := range resp.GetNodes() {
			s := node.GetSbomStatus().GetStatus()
			if isPending(s) {
				wl := node.GetWorkload()
				out = append(out, watchWorkload{
					cluster:   wl.GetCluster(),
					namespace: wl.GetNamespace(),
					name:      wl.GetName(),
					wtype:     wl.GetType(),
				})
			}
		}

		if !resp.GetPageInfo().GetHasNextPage() {
			break
		}
		offset += pageSize
	}
	return out, nil
}

func buildBaseOpts(o *flag.Options) []vulnerabilities.Option {
	var opts []vulnerabilities.Option
	if o.Cluster != "" {
		opts = append(opts, vulnerabilities.ClusterFilter(o.Cluster))
	}
	if o.Namespace != "" {
		opts = append(opts, vulnerabilities.NamespaceFilter(o.Namespace))
	}
	if o.Workload != "" {
		opts = append(opts, vulnerabilities.WorkloadFilter(o.Workload))
	}
	if o.WorkloadType != "" {
		opts = append(opts, vulnerabilities.WorkloadTypeFilter(o.WorkloadType))
	}
	return opts
}

func isPending(s vulnerabilities.SbomStatus) bool {
	return s == vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED ||
		s == vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING
}

// pickWorkload shows a fuzzy-searchable huh.Select and returns the chosen workload.
func pickWorkload(pending []watchWorkload) (watchWorkload, error) {
	options := make([]huh.Option[watchWorkload], 0, len(pending))
	for _, w := range pending {
		options = append(options, huh.NewOption(w.label(), w))
	}

	var chosen watchWorkload
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[watchWorkload]().
				Title("Select a workload to watch").
				Description(fmt.Sprintf("%d workloads with pending SBOM — type to filter", len(pending))).
				Options(options...).
				Filtering(true).
				Value(&chosen),
		),
	)
	if err := form.Run(); err != nil {
		return watchWorkload{}, fmt.Errorf("selection cancelled: %w", err)
	}
	return chosen, nil
}

// runWatchLoop polls GetVulnerabilitySummaryForImage for the workload's image
// (derived from ListVulnerabilitySummaries with exact workload filters) and
// prints a refreshed status screen every interval.
func runWatchLoop(ctx context.Context, c vulnerabilities.Client, wl watchWorkload, interval time.Duration) error {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	labelFmt := color.New(color.FgYellow).SprintfFunc()
	boldFmt := color.New(color.Bold).SprintfFunc()

	clearScreen := func() {
		fmt.Print("\033[H\033[2J")
	}

	for {
		clearScreen()

		fmt.Printf("%s\n", boldFmt("Watching SBOM status — press Ctrl+C to stop"))
		fmt.Printf("Workload : %s\n", wl.label())
		fmt.Printf("Refreshed: %s  (every %s)\n\n", time.Now().Format(time.RFC3339), interval)

		// Fetch the workload's current summary (gives us image + sbom status)
		summaries, err := c.ListVulnerabilitySummaries(ctx,
			vulnerabilities.ClusterFilter(wl.cluster),
			vulnerabilities.NamespaceFilter(wl.namespace),
			vulnerabilities.WorkloadFilter(wl.name),
			vulnerabilities.WorkloadTypeFilter(wl.wtype),
			vulnerabilities.Limit(1),
		)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Printf("Error fetching summary: %v\n", err)
		} else if len(summaries.GetNodes()) == 0 {
			fmt.Println("Workload not found — it may have been removed.")
		} else {
			node := summaries.GetNodes()[0]
			sbomStatus := node.GetSbomStatus()
			workloadSbomStatus := formatSbomStatus(sbomStatus.GetStatus())
			imageName := node.GetWorkload().GetImageName()
			imageTag := node.GetWorkload().GetImageTag()
			imageRef := imageName + ":" + imageTag

			// Compute elapsed time from ProcessingStartedAt if available.
			var elapsedStr string
			if ts := sbomStatus.GetProcessingStartedAt(); ts != nil {
				started := ts.AsTime()
				elapsed := time.Since(started).Round(time.Second)
				elapsedStr = elapsed.String()
			}

			// Print workload-level status
			tbl := table.New("Field", "Value")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(labelFmt)
			tbl.AddRow("Image", imageRef)
			tbl.AddRow("SBOM Status", workloadSbomStatus)
			if elapsedStr != "" {
				tbl.AddRow("Processing for", elapsedStr)
			}
			tbl.AddRow("Has SBOM", fmt.Sprintf("%v", node.GetVulnerabilitySummary().GetHasSbom()))
			tbl.Print()

			// If we have an image ref, also fetch per-image summary for richer detail
			if imageName != "" && imageTag != "" {
				fmt.Println()
				imgResp, err := c.GetVulnerabilitySummaryForImage(ctx, imageName, imageTag)
				if err != nil {
					if status.Code(err) == codes.NotFound {
						fmt.Printf("\nImage summary: no SBOM ingested yet for %s\n", imageRef)
					} else if ctx.Err() == nil {
						fmt.Printf("\nImage summary error: %v\n", err)
					}
				} else {
					s := imgResp.GetVulnerabilitySummary()
					if s != nil && s.GetHasSbom() {
						fmt.Printf("Vulnerabilities — Critical: %d  High: %d  Medium: %d  Low: %d  Unassigned: %d  RiskScore: %d\n",
							s.GetCritical(), s.GetHigh(), s.GetMedium(), s.GetLow(), s.GetUnassigned(), s.GetRiskScore())
					}

					// Print per-workload statuses for this image
					workloads := imgResp.GetWorkloads()
					if len(workloads) > 0 {
						fmt.Println()
						wtbl := table.New("Workload", "Type", "Namespace", "Cluster", "SBOM Status")
						wtbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(labelFmt)
						for _, w := range workloads {
							wref := w.GetWorkload()
							highlight := wref.GetName() == wl.name && wref.GetNamespace() == wl.namespace && wref.GetCluster() == wl.cluster
							name := wref.GetName()
							if highlight {
								name = "► " + name
							}
							wtbl.AddRow(name, wref.GetType(), wref.GetNamespace(), wref.GetCluster(), formatSbomStatus(w.GetSbomStatus().GetStatus()))
						}
						wtbl.Print()
					}
				}
			}

			// Exit on any terminal state, printing total duration.
			currentStatus := sbomStatus.GetStatus()
			if currentStatus == vulnerabilities.SbomStatus_SBOM_STATUS_READY {
				fmt.Printf("\n%s SBOM ready!", color.GreenString("✓"))
				if elapsedStr != "" {
					fmt.Printf("  Took %s", elapsedStr)
				}
				fmt.Println()
				return nil
			}
			if !isPending(currentStatus) {
				fmt.Printf("\n%s SBOM processing ended — status: %s",
					color.YellowString("!"), strings.ToUpper(formatSbomStatus(currentStatus)))
				if elapsedStr != "" {
					fmt.Printf("  Took %s", elapsedStr)
				}
				fmt.Println()
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

