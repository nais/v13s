package commands

import (
	"context"
	"fmt"
	"strings"

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

	vulnID, err := findVulnerabilityID(ctx, c, imageName, imageTag, opts.Package, opts.CveId)
	if err != nil {
		return fmt.Errorf("failed to get vulnerability: %w", err)
	}

	err = c.SuppressVulnerability(
		ctx,
		vulnID,
		"Suppressing via CLI",
		"cli-user",
		vulnerabilities.SuppressState_FALSE_POSITIVE,
		true,
	)
	if err != nil {
		return fmt.Errorf("failed to suppress vulnerability: %w", err)
	}

	fmt.Printf("Vulnerability %s suppressed successfully\n", vulnID)
	return nil
}

type imageVulnerabilityLister interface {
	ListVulnerabilitiesForImage(ctx context.Context, imageName, imageTag string, opts ...vulnerabilities.Option) (*vulnerabilities.ListVulnerabilitiesForImageResponse, error)
}

func findVulnerabilityID(ctx context.Context, c imageVulnerabilityLister, imageName, imageTag, pkg, cveID string) (string, error) {
	const pageSize = int32(100)
	var offset int32
	for {
		resp, err := c.ListVulnerabilitiesForImage(ctx, imageName, imageTag,
			vulnerabilities.IncludeSuppressed(),
			vulnerabilities.Limit(pageSize),
			vulnerabilities.Offset(offset),
		)
		if err != nil {
			return "", err
		}
		for _, v := range resp.GetNodes() {
			if v.GetPackage() == pkg && matchesCve(v.GetCve(), cveID) {
				return v.GetId(), nil
			}
		}
		if !resp.GetPageInfo().GetHasNextPage() {
			return "", fmt.Errorf("vulnerability not found")
		}
		offset += pageSize
	}
}

func matchesCve(cve *vulnerabilities.Cve, id string) bool {
	if strings.EqualFold(cve.GetId(), id) {
		return true
	}
	for canonical, alias := range cve.GetReferences() {
		if strings.EqualFold(canonical, cve.GetId()) && strings.EqualFold(alias, id) {
			return true
		}
	}
	return false
}
