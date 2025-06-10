package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/pkg/api/auth"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/cli/commands"
	"github.com/nais/v13s/pkg/cli/flag"
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

	opts := &flag.Options{}

	cmds := make([]*cli.Command, 0)
	cmds = append(cmds, commands.ListCommands(c, opts)...)
	cmds = append(cmds, commands.GetCommands(c, opts)...)
	cmds = append(cmds, commands.ManagementCommands(c, opts)...)

	cmd := &cli.Command{
		Name:  "v13s",
		Usage: "vulnerability analysis tool",
		Description: "v13s is a vulnerability analysis tool that provides insights into vulnerabilities in your workloads." +
			" It can list vulnerabilities for images, workloads, clusters, and namespaces.",
		Commands: cmds,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
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
