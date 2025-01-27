package dependencytrack

import "github.com/nais/v13s/internal/dependencytrack/client"

type InternalClient interface {
	client.APIClient
}
