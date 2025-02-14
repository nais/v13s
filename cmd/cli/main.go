package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/fatih/color"
	"github.com/nais/v13s/pkg/api/auth"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/rodaine/table"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"os"
	"strings"
	"time"
)

func main() {
	url := "localhost:50051"
	//url := "vulnerabilities.nav.cloud.nais.io"
	ctx := context.Background()
	c, err := createClient(url, ctx)
	if err != nil {
		log.Fatalf("creating client: %v", err)
	}

	defer c.Close()

	var cluster string
	var namespace string
	var limit int64

	cmd := &cli.Command{
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
						Flags: []cli.Flag{
							&cli.IntFlag{
								Name:        "limit",
								Aliases:     []string{"l"},
								Value:       30,
								Usage:       "limit number of results",
								Destination: &limit,
							},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() == 0 {
								return fmt.Errorf("missing image name")
							}
							parts := strings.Split(cmd.Args().First(), ":")
							resp, err := c.ListVulnerabilitiesForImage(ctx, parts[0], parts[1], vulnerabilities.Limit(int32(limit)))
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

							return nil
						},
					},
					{
						Name:    "all",
						Aliases: []string{"a"},
						Usage:   "list all vulnerabilities with optional filters",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "env",
								Aliases:     []string{"e"},
								Value:       "",
								Usage:       "cluster name",
								Destination: &cluster,
							},
							&cli.StringFlag{
								Name:        "team",
								Aliases:     []string{"t"},
								Value:       "",
								Usage:       "team name",
								Destination: &namespace,
							},
							&cli.IntFlag{
								Name:        "limit",
								Aliases:     []string{"l"},
								Value:       30,
								Usage:       "limit number of results",
								Destination: &limit,
							},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							filters := make([]vulnerabilities.Option, 0)
							if cmd.Args().Len() > 0 {
								arg := cmd.Args().First()
								if strings.Contains(arg, ":") && strings.Contains(arg, "/") {
									parts := strings.Split(arg, ":")
									filters = append(filters, vulnerabilities.ImageFilter(parts[0], parts[1]))
								} else {
									filters = append(filters, vulnerabilities.WorkloadFilter(arg))
								}
							}
							if cluster != "" {
								filters = append(filters, vulnerabilities.ClusterFilter(cluster))
							}
							if namespace != "" {
								filters = append(filters, vulnerabilities.NamespaceFilter(namespace))
							}
							return listVulnz(ctx, c, int(limit), filters...)
						},
					},
					{
						Name:    "summary",
						Aliases: []string{"s"},
						Usage:   "list vulnerability summaries",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							fmt.Println("list summaries", cmd.Args().First())
							return nil
						},
					},
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func listVulnz(ctx context.Context, c vulnerabilities.Client, limit int, filters ...vulnerabilities.Option) error {
	offset := 0
	if limit <= 0 {
		limit = 30
	}
	for {
		filters = append(filters, vulnerabilities.Limit(int32(limit)), vulnerabilities.Offset(int32(offset)))
		start := time.Now()
		resp, err := c.ListVulnerabilities(ctx, filters...)
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
				v.Cve.Id,
				v.Cve.Severity,
				image,
				w.Name,
				w.Type,
				w.Namespace,
				w.Cluster,
			)
		}

		tbl.Print()
		numFetched := offset + limit
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
			offset += limit
		} else {
			fmt.Println("Invalid input. Use 'n' for next page or 'q' to quit.")
		}
	}
	return nil
}

func createClient(url string, ctx context.Context) (vulnerabilities.Client, error) {
	dialOptions := make([]grpc.DialOption, 0)
	if strings.Contains(url, "localhost") {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// TODO: G402 (CWE-295): TLS MinVersion too low. (Confidence: HIGH, Severity: HIGH)
		tlsOpts := &tls.Config{}
		cred := credentials.NewTLS(tlsOpts)
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(cred))
	}
	creds, err := auth.PerRPCGoogleIDToken(ctx, "slsa-verde@nais-management-233d.iam.gserviceaccount.com", "v13s")
	if err != nil {
		return nil, err
	}
	dialOptions = append(dialOptions, grpc.WithPerRPCCredentials(creds))

	return vulnerabilities.NewClient(
		url,
		dialOptions...,
	)
}
