build:
	go build -o bin/api ./cmd/api

build-cli:
	go -C ./pkg/cli build -o ../../bin/vulnz

install-cli:
	go -C ./pkg/cli build -o ${GOBIN}/vulnz

tidy:
	@echo "Running go mod tidy for all modules..."
	find . -name go.mod -execdir go mod tidy \;

test:
	go test -cover ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

check: vet fmt vulncheck deadcode staticcheck goimport

vet:
	@echo "Running go vet..."
	go vet ./...

goimport:
	@echo "Running goimport..."
	find . -type f -name '*.go' ! -path './internal/sources/dependencytrack/client/*'  ! -path './internal/database/sql/*' ! -name '*.pb.go' -exec go run golang.org/x/tools/cmd/goimports@latest -l -w  {} +

fmt:
	@echo "Running go fmt..."
	go fmt ./...

staticcheck:
	@echo "Running staticcheck..."
	go run honnef.co/go/tools/cmd/staticcheck@latest -f=stylish  ./...

# -exclude=GO-2025-3770 Several
# Sigstore-related modules (e.g., cosign, rekor, sigstore-go, timestamp-authority) are pulling in the vulnerable version
# Ignore until we can update to a version that is not vulnerable
vulncheck:
	@echo "Running vulncheck..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./... | grep -v 'GO-2025-3770'

deadcode:
	@echo "Running deadcode..."
	go run golang.org/x/tools/cmd/deadcode@latest -filter "pkg/api/vulnerabilities/options" -test ./...

# Is not in the total check, error for pkg/cli
gosec:
	@echo "Running gosec..."
	go run github.com/securego/gosec/v2/cmd/gosec@latest --exclude G404,G101,G115,G402 --exclude-generated -terse ./...

generate: generate-proto generate-sql generate-mocks

generate-proto:
	protoc \
		-I pkg/api/vulnerabilities/schemas/ \
		./pkg/api/vulnerabilities/schemas/*.proto \
		--go_out=. \
		--go-grpc_out=.


generate-sql:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc generate -f .configs/sqlc.yaml
	go run github.com/sqlc-dev/sqlc/cmd/sqlc vet -f .configs/sqlc.yaml

generate-mocks:
	find internal pkg -type f -name "mock_*.go" -delete
	go run github.com/vektra/mockery/v2 --config ./.configs/mockery.yaml
	find internal pkg -type f -name "mock_*.go" -exec go run mvdan.cc/gofumpt@latest -w {} \;

refresh-db:
	docker compose down -v

# make connect-db I=v13s-d94dc8a5 P=nais-management-7178 S=v13s-sa
connect-db:
	@CONNECTION_NAME=$$(gcloud sql instances describe $(I) \
	  --format="get(connectionName)" \
	  --project $(P)) && \
	cloud-sql-proxy $$CONNECTION_NAME \
	    --auto-iam-authn \
	    --impersonate-service-account="$(S)@$(P).iam.gserviceaccount.com"

