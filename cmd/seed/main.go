package main

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/database/typeext"
	"os"
	"strings"

	"github.com/nais/v13s/internal/dependencytrack/client"

	"github.com/joho/godotenv"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack"
	log "github.com/sirupsen/logrus"
)

func main() {
	ctx := context.Background()
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	dpClient, err := dependencytrack.NewClient(
		os.Getenv("V13S_DEPENDENCYTRACK_URL"),
		os.Getenv("V13S_DEPENDENCYTRACK_API_KEY"),
	)
	if err != nil {
		panic(err)
	}

	projects, err := dpClient.GetProjectsByTag(ctx, "team:nais-system", 10, 0)
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

	log.Infof("reseting database")
	err = db.ResetDatabase(ctx)
	if err != nil {
		panic(err)
	}

	for _, project := range projects {
		if project.Metrics == nil {
			fmt.Println("project metrics is nil", project)
			continue
		}

		image := sql.CreateImageParams{
			Name:     *project.Name,
			Tag:      *project.Version,
			Metadata: make(typeext.MapStringString),
		}

		if err := db.CreateImage(ctx, image); err != nil {
			panic(err)
		}

		workloads := toCreateWorkloadParams(project, image)
		for _, workload := range workloads {
			_, err := db.CreateWorkload(ctx, *workload)
			if err != nil {
				panic(err)
			}
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

func toCreateWorkloadParams(p client.Project, image sql.CreateImageParams) []*sql.CreateWorkloadParams {
	workloads := make([]*sql.CreateWorkloadParams, 0)
	for _, t := range p.Tags {
		if strings.HasPrefix(*t.Name, "workload:") {
			parts := strings.Split(strings.TrimPrefix(*t.Name, "workload:"), "|")
			if len(parts) != 4 {
				log.Printf("Invalid workload tag: %s", *t.Name)
				continue
			}
			fmt.Printf("workload: %v\n", parts)
			workloads = append(workloads, &sql.CreateWorkloadParams{
				Cluster:      parts[0],
				Namespace:    parts[1],
				WorkloadType: parts[2],
				Name:         parts[3],
				ImageName:    image.Name,
				ImageTag:     image.Tag,
			})

		}
	}
	return workloads
}
