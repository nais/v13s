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

	log.Infof("initializing database")

	pool, err := database.New(ctx, "postgres://v13s:v13s@127.0.0.1:4002/v13s?sslmode=disable", log.WithField("component", "database"))
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

	images := createNaisApiWorkloads(ctx, db, "dev", "devteam")
	createNaisApiWorkloads(ctx, db, "superprod", "devteam")
	createVulnData(ctx, db, images)
}

func seedFromDependencyTrack(ctx context.Context, db sql.Querier) {
	dpClient, err := dependencytrack.NewClient(
		os.Getenv("V13S_DEPENDENCYTRACK_URL"),
		os.Getenv("V13S_DEPENDENCYTRACK_TEAM"),
		os.Getenv("V13S_DEPENDENCYTRACK_USERNAME"),
		os.Getenv("V13S_DEPENDENCYTRACK_PASSWORD"),
	)
	if err != nil {
		panic(err)
	}

	projects, err := dpClient.GetProjectsByTag(ctx, "team:nais-system", 10, 0)
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

func createVulnData(ctx context.Context, db sql.Querier, images []string) {
	chicken := 1
	for _, image := range images {
		batch := generateVulnerabilities(chicken, image, "1")
		chicken++

		db.BatchUpsertCve(ctx, batch.cve).Exec(func(i int, err error) {
			if err != nil {
				panic(err)
			}
		})

		db.BatchUpsertVulnerabilities(ctx, batch.vuln).Exec(func(i int, err error) {
			if err != nil {
				panic(err)
			}
		})

		sumRow, err := db.GenerateVulnerabilitySummaryForImage(ctx, sql.GenerateVulnerabilitySummaryForImageParams{
			ImageName: image,
			ImageTag:  "1",
		})
		if err != nil {
			panic(err)
		}

		summary := sql.CreateVulnerabilitySummaryParams{
			ImageName:  image,
			ImageTag:   "1",
			Critical:   int32(sumRow.Critical),
			High:       int32(sumRow.High),
			Medium:     int32(sumRow.Medium),
			Low:        int32(sumRow.Low),
			Unassigned: int32(sumRow.Unassigned),
			RiskScore:  sumRow.RiskScore,
		}

		_, err = db.CreateVulnerabilitySummary(ctx, summary)
		if err != nil {
			panic(fmt.Errorf("summary error: %v", err))
		}
	}

}

func createNaisApiWorkloads(ctx context.Context, db sql.Querier, cluster, namespace string) []string {
	images := make([]string, 0)
	for chicken := 1; chicken < 9; chicken++ {
		name := "ghcr.io/nais/nais-deploy-chicken-" + fmt.Sprintf("%d", chicken)
		images = append(images, name)
		if err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     name,
			Tag:      "1",
			Metadata: map[string]string{},
		}); err != nil {
			panic(err)
		}

		_, err := db.CreateWorkload(ctx, sql.CreateWorkloadParams{
			Cluster:      cluster,
			Namespace:    namespace,
			WorkloadType: "app",
			Name:         "nais-deploy-chicken-" + fmt.Sprintf("%d", chicken),
			ImageName:    name,
			ImageTag:     "1",
		})
		if err != nil {
			panic(err)
		}
	}
	return images
}

type BatchVulnerabilities struct {
	vuln []sql.BatchUpsertVulnerabilitiesParams
	cve  []sql.BatchUpsertCveParams
}

// generateVulnerabilities creates a different number of vulnerabilities per workload
func generateVulnerabilities(chicken int, imageName string, imageTag string) BatchVulnerabilities {
	vulns := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	cves := make([]sql.BatchUpsertCveParams, 0)

	for j := 1; j <= chicken; j++ {
		for s := 1; s <= 5; s++ {
			v, c := createVulnerability(s, fmt.Sprintf("CWE-%d-%d-%d", chicken, j, s), imageName, imageTag)
			vulns = append(vulns, v)
			cves = append(cves, c)
		}
	}

	return BatchVulnerabilities{
		vuln: vulns,
		cve:  cves,
	}
}

// createVulnerability generates a predictable vulnerability instance
func createVulnerability(severity int, cveID string, imageName string, imageTag string) (sql.BatchUpsertVulnerabilitiesParams, sql.BatchUpsertCveParams) {
	return sql.BatchUpsertVulnerabilitiesParams{
			ImageName: imageName,
			ImageTag:  imageTag,
			Package:   fmt.Sprintf("package-%s", cveID),
			Source:    "seed",
			CveID:     cveID,
		}, sql.BatchUpsertCveParams{
			CveID:    cveID,
			CveTitle: "Title for " + cveID,
			CveDesc:  "description for " + cveID,
			CveLink:  "https://example.com/" + cveID,
			Severity: int32(severity),
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
