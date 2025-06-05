package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/pkg/api/auth"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/rodaine/table"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type config struct {
	VulnerabilitiesUrl     string `envconfig:"VULNERABILITIES_URL" required:"false" default:"localhost:50051"`
	ServiceAccount         string `envconfig:"SERVICE_ACCOUNT" required:"true"`
	ServiceAccountAudience string `envconfig:"SERVICE_ACCOUNT_AUDIENCE" required:"true"`
}

type options struct {
	cluster      string
	namespace    string
	workload     string
	limit        int
	order        string
	since        string
	workloadType string
}

func main() {
	ctx := context.Background()

	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	var cfg config
	err = envconfig.Process("V13S", &cfg)
	if err != nil {
		log.Fatal(err.Error())
	}

	c, err := createClient(cfg, ctx)
	if err != nil {
		log.Fatalf("creating client: %v", err)
	}

	defer c.Close()

	opts := &options{}

	cmd := &cli.Command{
		Name:  "v13s",
		Usage: "vulnerability analysis tool",
		Description: "v13s is a vulnerability analysis tool that provides insights into vulnerabilities in your workloads." +
			" It can list vulnerabilities for images, workloads, clusters, and namespaces." +
			" the tool does not include in the statistics namespaces listed her: " +
			"https://github.com/nais/slsa-verde/blob/ec79032d569517091f504be4581a11889b91da7d/cmd/slsa-verde/main.go#L245",
		Commands: []*cli.Command{
			{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "list vulnerabilities",
				Commands: []*cli.Command{
					{
						Name:    "image",
						Aliases: []string{"v"},
						Usage:   "list vulnerabilities for image",
						Flags:   commonFlags(opts, "cluster", "namespace", "workload"),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return listVulnerabilitiesForImage(ctx, cmd, c, opts)
						},
					},
					{
						Name:  "suppressed",
						Usage: "list suppressed vulnerabilities",
						Flags: commonFlags(opts),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return listSuppressedVulnerabilities(ctx, cmd, c, opts)
						},
					},
					{
						Name:    "all",
						Aliases: []string{"a"},
						Usage:   "list all vulnerabilities with optional filters",
						Flags:   commonFlags(opts),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return listVulnz(ctx, cmd, c, opts)
						},
					},
					{
						Name:    "summary",
						Aliases: []string{"s"},
						Usage:   "list vulnerability summary for filter",
						Flags:   commonFlags(opts),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return listSummaries(ctx, cmd, c, opts)
						},
					},
				},
			},
			{
				Name:    "get",
				Aliases: []string{"g"},
				Usage:   "vulnerability statistics",
				Commands: []*cli.Command{
					{
						Name:    "coverage",
						Aliases: []string{"c"},
						Usage:   "get sbom coverage for filter",
						Flags:   commonFlags(opts),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return coverageSummary(ctx, cmd, c, opts)
						},
					},
					{
						Name:    "summary",
						Aliases: []string{"s"},
						Usage:   "get vulnerability summary for filter",
						Flags:   commonFlags(opts),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return getSummary(ctx, cmd, c, opts)
						},
					},
					{
						Name:    "timeseries",
						Aliases: []string{"t"},
						Usage:   "get vulnerability summary time series for filter",
						Flags:   commonFlags(opts),
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return getTimeseries(ctx, cmd, c, opts)
						},
					},
				},
			},
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
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func getTimeseries(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *options) error {
	opts := parseOptions(cmd, o)
	format := time.DateOnly
	start := time.Now()

	resp, err := c.GetVulnerabilitySummaryTimeSeries(ctx, opts...)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	headers := []any{
		"BucketTime",
		"Critical",
		"High",
		"Medium",
		"Low",
		"Unassigned",
		"RiskScore",
		"WorkloadCount",
	}
	tbl := table.New(headers...)
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, p := range resp.GetPoints() {
		vals := []any{
			p.GetBucketTime().AsTime().Format(format),
			p.GetCritical(),
			p.GetHigh(),
			p.GetMedium(),
			p.GetLow(),
			p.GetUnassigned(),
			p.GetRiskScore(),
			p.GetWorkloadCount(),
		}
		tbl.AddRow(
			vals...,
		)
	}

	tbl.Print()
	duration := time.Since(start).Seconds()
	fmt.Printf("Fetched %d points in %f seconds.\n", len(resp.GetPoints()), duration)
	return nil
}

func listSuppressedVulnerabilities(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *options) error {
	opts := parseOptions(cmd, o)
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
			n.Reason,
			n.Suppress,
			n.SuppressedBy,
			n.ImageName,
		)
	}

	tbl.Print()
	fmt.Println("\nFetched vulnerabilities in", time.Since(start).Seconds(), "seconds")

	return nil
}

func listVulnerabilitiesForImage(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *options) error {
	offset := 0
	for {
		opts := parseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(int32(offset)))

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
		numFetched := offset + o.limit
		if numFetched > int(resp.PageInfo.TotalCount) {
			numFetched = int(resp.PageInfo.TotalCount)
		}
		fmt.Printf("Fetched %d of total '%d' summaries in %f seconds.\n", numFetched, resp.PageInfo.TotalCount, time.Since(start).Seconds())

		// Check if there is another page
		if !resp.GetPageInfo().GetHasNextPage() {
			fmt.Printf("No more pages available.\n")
			break
		}

		// Ask user for input to continue pagination
		fmt.Println("Press 'n' for next page, 'q' to quit:")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "q" {
			break
		} else if input == "n" {
			offset += o.limit
		} else {
			fmt.Println("Invalid input. Use 'n' for next page or 'q' to quit.")
		}
	}
	return nil
}

func coverageSummary(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *options) error {
	opts := parseOptions(cmd, o)
	start := time.Now()
	resp, err := c.GetVulnerabilitySummary(ctx, opts...)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Workloads", "SBOM", "No SBOM", "Coverage")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	tbl.AddRow(
		resp.GetWorkloadCount(),
		resp.GetSbomCount(),
		resp.GetWorkloadCount()-resp.GetSbomCount(),
		resp.GetCoverage(),
	)

	tbl.Print()
	fmt.Println("\nFetched coverage in", time.Since(start).Seconds(), "seconds")

	return nil
}

func getSummary(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *options) error {
	opts := parseOptions(cmd, o)
	start := time.Now()
	resp, err := c.GetVulnerabilitySummary(ctx, opts...)
	if err != nil {
		return err
	}

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Workload Count", "SBOM Count", "Critical", "High", "Medium", "Low", "Unassigned", "Risk Score", "Coverage")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	tbl.AddRow(
		resp.GetWorkloadCount(),
		resp.GetSbomCount(),
		resp.GetVulnerabilitySummary().GetCritical(),
		resp.GetVulnerabilitySummary().GetHigh(),
		resp.GetVulnerabilitySummary().GetMedium(),
		resp.GetVulnerabilitySummary().GetLow(),
		resp.GetVulnerabilitySummary().GetUnassigned(),
		resp.GetVulnerabilitySummary().GetRiskScore(),
		resp.GetCoverage(),
	)

	tbl.Print()
	fmt.Println("\nFetched summary in", time.Since(start).Seconds(), "seconds")

	return nil
}

func listSummaries(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *options) error {
	offset := 0
	for {
		opts := parseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(int32(offset)))

		start := time.Now()
		resp, err := c.ListVulnerabilitySummaries(ctx, opts...)
		if err != nil {
			return err
		}

		headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
		columnFmt := color.New(color.FgYellow).SprintfFunc()

		headers := []any{"Workload", "Type", "Cluster", "Namespace", "Has SBOM", "Critical", "High", "Medium", "Low", "Unassigned", "RiskScore"}
		if o.since != "" {
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
			if o.since != "" {
				vals = append(vals, n.Workload.GetImageTag())
				vals = append(vals, n.GetVulnerabilitySummary().GetLastUpdated().AsTime().Format(time.RFC3339))
			}
			tbl.AddRow(
				vals...,
			)
		}

		tbl.Print()
		numFetched := offset + o.limit
		if numFetched > int(resp.PageInfo.TotalCount) {
			numFetched = int(resp.PageInfo.TotalCount)
		}
		fmt.Printf("Fetched %d of total '%d' summaries in %f seconds.\n", numFetched, resp.PageInfo.TotalCount, time.Since(start).Seconds())

		// Check if there is another page
		if !resp.GetPageInfo().GetHasNextPage() {
			fmt.Printf("No more pages available.\n")
			break
		}

		// Ask user for input to continue pagination
		fmt.Println("Press 'n' for next page, 'q' to quit:")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "q" {
			break
		} else if input == "n" {
			offset += o.limit
		} else {
			fmt.Println("Invalid input. Use 'n' for next page or 'q' to quit.")
		}
	}
	return nil
}

// convertDuration converts a duration string with Y (years), M (months), W (weeks), D (days) into hours (h).
func convertDuration(duration string) (string, error) {
	multipliers := map[string]int{
		"Y": 365 * 24, // 1 year = 8760 hours
		"M": 30 * 24,  // 1 month = 30 days = 30 * 24 hours
		"W": 7 * 24,   // 1 week = 7 days = 7 * 24 hours
		"D": 24,       // 1 day = 24 hours
	}

	for unit, multiplier := range multipliers {
		if strings.HasSuffix(duration, unit) {
			trimmed, _ := strings.CutSuffix(duration, unit)
			num, err := strconv.Atoi(trimmed)
			if err != nil {
				return "", fmt.Errorf("invalid duration: %s", duration)
			}
			return strconv.Itoa(num*multiplier) + "h", nil
		}
	}

	// If no recognized suffix, return as-is
	return duration, nil
}

func listVulnz(ctx context.Context, cmd *cli.Command, c vulnerabilities.Client, o *options) error {
	offset := 0
	for {
		start := time.Now()
		opts := parseOptions(cmd, o)
		opts = append(opts, vulnerabilities.Offset(int32(offset)))
		resp, err := c.ListVulnerabilities(ctx, opts...)
		if err != nil {
			return err
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
		numFetched := offset + o.limit
		if numFetched > int(resp.PageInfo.TotalCount) {
			numFetched = int(resp.PageInfo.TotalCount)
		}
		fmt.Printf("Fetched %d of total '%d' vulnerabilities in %f seconds.\n", numFetched, resp.PageInfo.TotalCount, time.Since(start).Seconds())

		// Check if there is another page
		if !resp.GetPageInfo().GetHasNextPage() {
			fmt.Printf("No more pages available.\n")
			break
		}

		// Ask user for input to continue pagination
		fmt.Println("Press 'n' for next page, 'q' to quit:")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "q" {
			break
		} else if input == "n" {
			offset += o.limit
		} else {
			fmt.Println("Invalid input. Use 'n' for next page or 'q' to quit.")
		}
	}
	return nil
}

func createClient(cfg config, ctx context.Context) (vulnerabilities.Client, error) {
	dialOptions := make([]grpc.DialOption, 0)
	if strings.Contains(cfg.VulnerabilitiesUrl, "localhost") {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsOpts := &tls.Config{}
		cred := credentials.NewTLS(tlsOpts)
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(cred))
		creds, err := auth.PerRPCGoogleIDToken(ctx, cfg.ServiceAccount, cfg.ServiceAccountAudience)
		if err != nil {
			return nil, err
		}
		dialOptions = append(dialOptions, grpc.WithPerRPCCredentials(creds))
	}

	return vulnerabilities.NewClient(
		cfg.VulnerabilitiesUrl,
		dialOptions...,
	)
}

func parseOptions(cmd *cli.Command, o *options) []vulnerabilities.Option {
	opts := make([]vulnerabilities.Option, 0)
	if cmd.Args().Len() > 0 {
		arg := cmd.Args().First()
		if strings.Contains(arg, ":") && strings.Contains(arg, "/") {
			parts := strings.Split(arg, ":")
			opts = append(opts, vulnerabilities.ImageFilter(parts[0], parts[1]))
		} else {
			opts = append(opts, vulnerabilities.WorkloadFilter(arg))
		}
	}
	if o.cluster != "" {
		opts = append(opts, vulnerabilities.ClusterFilter(o.cluster))
	}
	if o.namespace != "" {
		opts = append(opts, vulnerabilities.NamespaceFilter(o.namespace))
	}
	if o.workload != "" {
		opts = append(opts, vulnerabilities.WorkloadFilter(o.workload))
	}
	if o.workloadType != "" {
		opts = append(opts, vulnerabilities.WorkloadTypeFilter(o.workloadType))
	}
	if o.limit > 0 {
		opts = append(opts, vulnerabilities.Limit(int32(o.limit)))
	} else {
		opts = append(opts, vulnerabilities.Limit(30))
	}

	if o.order != "" {
		direction := vulnerabilities.Direction_ASC
		if strings.Contains(o.order, ":") {
			parts := strings.Split(o.order, ":")
			o.order = parts[0]
			if parts[1] == "desc" {
				direction = vulnerabilities.Direction_DESC
			}
		}
		opts = append(opts, vulnerabilities.Order(vulnerabilities.OrderByField(o.order), direction))
	}

	if o.since != "" {
		s, err := convertDuration(o.since)
		if err != nil {
			log.Fatalf("invalid duration: %s", o.since)
		}
		duration, err := time.ParseDuration(s)
		if err != nil {
			log.Fatalf("invalid duration: %s", o.since)
		}
		sinceTime := time.Now().Add(-duration)
		opts = append(opts, vulnerabilities.Since(sinceTime))
	}
	return opts
}

func commonFlags(opts *options, excludes ...string) []cli.Flag {
	flags := make([]cli.Flag, 0)
	cFlags := []cli.Flag{
		&cli.StringFlag{
			Name:        "cluster",
			Aliases:     []string{"c"},
			Value:       "",
			Usage:       "cluster name",
			Destination: &opts.cluster,
		},
		&cli.StringFlag{
			Name:        "namespace",
			Aliases:     []string{"n"},
			Value:       "",
			Usage:       "namespace",
			Destination: &opts.namespace,
		},
		&cli.StringFlag{
			Name:        "workload",
			Aliases:     []string{"w"},
			Value:       "",
			Usage:       "workload name",
			Destination: &opts.workload,
		},
		&cli.StringFlag{
			Name:        "type",
			Aliases:     []string{"t"},
			Value:       "",
			Usage:       "workload type",
			Destination: &opts.workloadType,
		},
		&cli.IntFlag{
			Name:        "limit",
			Aliases:     []string{"l"},
			Value:       30,
			Usage:       "limit number of results",
			Destination: &opts.limit,
		},
		&cli.StringFlag{
			Name:        "order",
			Aliases:     []string{"o"},
			Value:       "",
			Usage:       "order by field, use 'field:desc' for descending order",
			Destination: &opts.order,
		},
		&cli.StringFlag{
			Name:        "since",
			Aliases:     []string{"s"},
			Value:       "",
			Usage:       "Specify a relative time (e.g. '1Y' for last year, '1M' for last month, '2D' for last 2 days, '12h' for last 12 hours, '30m' for last 30 minutes)",
			Destination: &opts.since,
		},
	}
	for _, f := range cFlags {
		exclude := false
		for _, e := range excludes {
			if f.String() == e {
				exclude = true
				break
			}
		}
		if !exclude {
			flags = append(flags, f)
		}
	}
	return flags
}
