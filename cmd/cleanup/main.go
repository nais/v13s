package main

import (
	"context"
	"fmt"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/dynamic"
	schemepkg "k8s.io/client-go/kubernetes/scheme"
)

func main() {
	ctx := context.Background()
	cfg, err := config.NewConfig()
	if err != nil {
		log.WithError(err).Errorf("error when processing configuration")
	}

	log.Infof("initializing database")

	pool, err := database.New(ctx, cfg.DatabaseUrl, log.WithField("component", "database"))
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	db := sql.New(pool)
	clients := newClients(cfg)

	for cluster, client := range clients {
		apps, err := client.list(ctx, "nais.io", "v1alpha1", "applications")
		if err != nil {
			panic(fmt.Errorf("error listing apps: %w", err))
		}
		jobs, err := client.list(ctx, "nais.io", "v1", "naisjobs")
		if err != nil {
			fmt.Printf("error listing naisjobs: %v\n", err)
		}

		workloads, err := db.ListWorkloadsByCluster(ctx, cluster)
		if err != nil {
			panic(fmt.Errorf("error listing workloads: %w", err))
		}

		fmt.Printf("-------------------------------------------\n")
		fmt.Printf("%d apps in cluster %s\n", len(apps.Items), cluster)
		fmt.Printf("%d jobs in cluster %s\n", len(jobs.Items), cluster)
		fmt.Printf("%d total workloads in database %s\n", len(workloads), cluster)
		fmt.Printf("-------------------------------------------\n")

		workloadsToDelete := make([]*sql.Workload, 0)
		for _, workload := range workloads {
			found := false
			if workload.WorkloadType == "app" || workload.WorkloadType == "job" {
				for _, app := range apps.Items {
					if workload.Name == app.GetName() && workload.Namespace == app.GetNamespace() && workload.WorkloadType == "app" {
						//fmt.Printf("found workload: %s in ns: %s and cluster: %s\n", workload.Name, workload.Namespace, cluster)
						found = true
						break
					}
				}
				for _, job := range jobs.Items {
					if workload.Name == job.GetName() && workload.Namespace == job.GetNamespace() && workload.WorkloadType == "job" {
						//fmt.Printf("found workload: %s in ns: %s and cluster: %s\n", workload.Name, workload.Namespace, cluster)
						found = true
						break
					}
				}

				if !found {
					fmt.Printf("%s not found in cluster %s\n", workload.Name, cluster)
					workloadsToDelete = append(workloadsToDelete, workload)
				}
			}
		}
		fmt.Printf("%d workloads to delete in cluster %s\n", len(workloadsToDelete), cluster)
		fmt.Printf("-------------------------------------------\n")
		for _, workload := range workloadsToDelete {
			fmt.Printf(
				"deleting workload %s:%s:%s:%s\n",
				workload.Name,
				workload.WorkloadType,
				workload.Namespace,
				cluster,
			)

			id, err := db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
				Name:         workload.Name,
				WorkloadType: workload.WorkloadType,
				Namespace:    workload.Namespace,
				Cluster:      workload.Cluster,
			})
			if err != nil {
				fmt.Printf("error deleting workload %s: %v\n", workload.Name, err)
			}

			fmt.Printf("deleted workload %s:%s:%s:%s:%s\n", workload.Name, workload.WorkloadType, workload.Namespace, cluster, id)
		}

		fmt.Printf("-------------------------------------------\n")
		fmt.Printf("deleted %d workloads in cluster %s\n with sourceID", len(workloadsToDelete), cluster)
		workloads, err = db.ListWorkloadsByCluster(ctx, cluster)
		if err != nil {
			panic(fmt.Errorf("error listing workloads: %w", err))
		}
		numAppsJobs := 0
		//fmt.Printf("------------ List of workloads ------------\n")
		for _, workload := range workloads {
			if workload.WorkloadType == "app" || workload.WorkloadType == "job" {
				//fmt.Printf("%s:%s:%s:%s\n", workload.Name, workload.WorkloadType, workload.Namespace, cluster)
				numAppsJobs++
			}
		}
		fmt.Printf("-------------------------------------------\n")
		fmt.Printf("remaining total workloads in database %s: %d\n", cluster, len(workloads))
		fmt.Printf("remaining apps/jobs in database %s: %d\n", cluster, numAppsJobs)
		fmt.Printf("apps in cluster %s: %d\n", cluster, len(apps.Items))
		fmt.Printf("jobs in cluster %s: %d\n", cluster, len(jobs.Items))
		fmt.Printf("-------------------------------------------\n")
	}

}

func newClients(cfg *config.Config) map[string]*Client {
	clusterConfig, err := config.CreateClusterConfigMap(cfg.Tenant, cfg.K8s)
	if err != nil {
		log.Fatalf("Failed to create cluster config map: %v", err)
	}
	clients := map[string]*Client{}

	for cluster := range clusterConfig {
		config, ok := clusterConfig[cluster]
		if !ok {
			panic(fmt.Errorf("no config for cluster %s", cluster))
		}
		if config.NegotiatedSerializer == nil {
			config.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{CodecFactory: schemepkg.Codecs}
		}

		config.UserAgent = "nais.io/v13s"
		client, err := dynamic.NewForConfig(config)
		if err != nil {
			panic(fmt.Errorf("creating REST client: %w", err))
		}
		clients[cluster] = &Client{
			client,
		}
	}
	return clients
}

type Client struct {
	dynamic.Interface
}

func (c *Client) list(ctx context.Context, group, version, resource string) (*unstructured.UnstructuredList, error) {
	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}
	list, err := c.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("error listing %s", resource)
		return &unstructured.UnstructuredList{
			Items:  []unstructured.Unstructured{},
			Object: map[string]interface{}{},
		}, nil
	}
	return list, nil
}
