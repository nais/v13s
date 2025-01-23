package main

import (
	"context"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack"
	log "github.com/sirupsen/logrus"
	"os"
)

func main() {
	ctx := context.Background()
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	dpClient, err := dependencytrack.NewClient(
		os.Getenv("V13S_DEPENDENCYTRACK_API_KEY"),
		os.Getenv("V13S_DEPENDENCYTRACK_URL"),
	)
	if err != nil {
		panic(err)
	}
	
	projects, err := dpClient.GetProjectsByTag(ctx, "nais-system", 10, 0)
	if err != nil {
		panic(err)
	}

	log.Infof("initializing database")

	pool, err := database.New(ctx, "postgres://v13s:v13s@127.0.0.1:3002/v13s?sslmode=disable", log.WithField("component", "database"))
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	db := sql.New(pool)
	for _, project := range projects {
		if project.Metrics == nil {
			fmt.Println("project metrics is nil", project)
			continue
		}

		arg := sql.CreateVulnerabilitySummaryParams{
			ImageName:  *project.Name,
			ImageTag:   *project.Version,
			Critical:   project.Metrics.Critical,
			High:       project.Metrics.High,
			Medium:     project.Metrics.Medium,
			Low:        project.Metrics.Low,
			Unassigned: *project.Metrics.Unassigned,
			RiskScore:  int32(*project.Metrics.InheritedRiskScore),
		}
		res, err := db.CreateVulnerabilitySummary(ctx, arg)
		if err != nil {
			panic(err)
		}
		log.Infof("created vulnerability summary: %v", res)
	}
}
