package flag

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

type Options struct {
	Cluster       string
	Namespace     string
	Workload      string
	Limit         int
	Order         string
	Since         string
	WorkloadType  string
	ShowJobs      bool
	WorkloadState string
	ImageState    string
}

func CommonFlags(opts *Options, excludes ...string) []cli.Flag {
	flags := make([]cli.Flag, 0)
	cFlags := []cli.Flag{
		&cli.StringFlag{
			Name:        "cluster",
			Aliases:     []string{"c"},
			Value:       "",
			Usage:       "cluster name",
			Destination: &opts.Cluster,
		},
		&cli.StringFlag{
			Name:        "namespace",
			Aliases:     []string{"n"},
			Value:       "",
			Usage:       "namespace",
			Destination: &opts.Namespace,
		},
		&cli.StringFlag{
			Name:        "workload",
			Aliases:     []string{"w"},
			Value:       "",
			Usage:       "workload name",
			Destination: &opts.Workload,
		},
		&cli.StringFlag{
			Name:        "type",
			Aliases:     []string{"t"},
			Value:       "",
			Usage:       "workload type",
			Destination: &opts.WorkloadType,
		},
		&cli.IntFlag{
			Name:        "limit",
			Aliases:     []string{"l"},
			Value:       30,
			Usage:       "limit number of results",
			Destination: &opts.Limit,
		},
		&cli.StringFlag{
			Name:        "order",
			Aliases:     []string{"o"},
			Value:       "",
			Usage:       "order by field, use 'field:desc' for descending order",
			Destination: &opts.Order,
		},
		&cli.StringFlag{
			Name:        "since",
			Aliases:     []string{"s"},
			Value:       "",
			Usage:       "Specify a relative time (e.g. '1Y' for last year, '1M' for last month, '2D' for last 2 days, '12h' for last 12 hours, '30m' for last 30 minutes)",
			Destination: &opts.Since,
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

func ParseOptions(cmd *cli.Command, o *Options) []vulnerabilities.Option {
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
	if o.Limit > 0 {
		opts = append(opts, vulnerabilities.Limit(int32(o.Limit)))
	} else {
		opts = append(opts, vulnerabilities.Limit(30))
	}

	if o.Order != "" {
		direction := vulnerabilities.Direction_ASC
		if strings.Contains(o.Order, ":") {
			parts := strings.Split(o.Order, ":")
			o.Order = parts[0]
			if parts[1] == "desc" {
				direction = vulnerabilities.Direction_DESC
			}
		}
		opts = append(opts, vulnerabilities.Order(vulnerabilities.OrderByField(o.Order), direction))
	}

	if o.Since != "" {
		s, err := convertDuration(o.Since)
		if err != nil {
			log.Fatalf("invalid duration: %s", o.Since)
		}
		duration, err := time.ParseDuration(s)
		if err != nil {
			log.Fatalf("invalid duration: %s", o.Since)
		}
		sinceTime := time.Now().Add(-duration)
		opts = append(opts, vulnerabilities.Since(sinceTime))
	}
	return opts
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
