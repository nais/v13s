package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/nais/v13s/internal/kubernetes"
	"time"
)

type Config struct {
	ListenAddr                string        `envconfig:"LISTEN_ADDR" default:"0.0.0.0:50051"`
	DatabaseUrl               string        `envconfig:"DATABASE_URL" required:"true"`
	UpdateInterval            time.Duration `envconfig:"UPDATE_INTERVAL" default:"1m"`
	RequiredAudience          string        `envconfig:"REQUIRED_AUDIENCE" default:"vulnz"`
	AuthorizedServiceAccounts []string      `envconfig:"AUTHORIZED_SERVICE_ACCOUNTS" required:"true"`
	LogFormat                 string        `envconfig:"LOG_FORMAT" default:"json"`
	LogLevel                  string        `envconfig:"LOG_LEVEL" default:"info"`
	Tenant                    string        `envconfig:"TENANT" default:"nav"`
	DependencyTrack           DependencyTrackConfig
	K8s                       K8sConfig
}

type DependencyTrackConfig struct {
	Url      string `env:"DEPENDENCYTRACK_URL"`
	Team     string `env:"DEPENDENCYTRACK_TEAM" default:"Administrators"`
	Username string `env:"DEPENDENCYTRACK_USERNAME" default:"v13s"`
	Password string `env:"DEPENDENCYTRACK_PASSWORD"`
}

type K8sConfig struct {
	UseKubeConfig  bool                       `env:"V13S_KUBERNETES_USE_KUBECONFIG"`
	Clusters       []string                   `env:"V13S_KUBERNETES_CLUSTERS"`
	StaticClusters []kubernetes.StaticCluster `env:"V13S_KUBERNETES_CLUSTERS_STATIC"`
}

func (k *K8sConfig) AllClusterNames() []string {
	clusters := append([]string{}, k.Clusters...)
	for _, c := range k.StaticClusters {
		clusters = append(clusters, c.Name)
	}
	return clusters
}

func NewConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}

	cfg := &Config{}
	err = envconfig.Process("V13S", cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
