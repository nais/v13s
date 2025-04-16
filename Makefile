IGNORED_PATH := "internal/sources/dependencytrack/client"
GO_PACKAGES := $(shell go list ./... | grep -v $(IGNORED_PATH))

build:
	go build -o bin/api ./cmd/api

build-cli:
	go build -o bin/vulnz ./cmd/cli

test:
	go test -cover ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

check: fmt vulncheck deadcode gosec staticcheck goimport

goimport:
	@echo "Running goimport..."
	find . -type f -name '*.go' ! -path './internal/sources/dependencytrack/client/*'  ! -path './internal/database/sql/*' ! -name '*.pb.go' -exec go run golang.org/x/tools/cmd/goimports@latest -l -w  {} +

fmt:
	@echo "Running go fmt..."
	go fmt $(GO_PACKAGES)

staticcheck:
	@echo "Running staticcheck..."
	go run honnef.co/go/tools/cmd/staticcheck@latest -f=stylish  $(GO_PACKAGES)

vulncheck:
	@echo "Running vulncheck..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

deadcode:
	@echo "Running deadcode..."
	go run golang.org/x/tools/cmd/deadcode@latest -filter "pkg/api/vulnerabilities/options" -test ./...

gosec:
	@echo "Running gosec..."
	go run github.com/securego/gosec/v2/cmd/gosec@latest --exclude G404,G101,G115,G402 --exclude-generated -terse ./...

generate: generate-proto generate_dp_track generate-sql generate-mocks

generate-proto:
	protoc \
		-I pkg/api/vulnerabilities/schemas/ \
		./pkg/api/vulnerabilities/schemas/*.proto \
		--go_out=. \
		--go-grpc_out=.

generate_dp_track:
	@echo "Generating Go code from the OpenAPI specification..."
	@openapi-generator generate \
        -i schema/dtrack.json \
        -g go \
        -o internal/sources/dependencytrack/client \
        --global-property apiTests=false,modelTests=false \
        --package-name client \
        --additional-properties=withGoMod=false \
        --additional-properties=generateInterfaces=true \
        --additional-properties=packageName=client || { \
			echo "Error: openapi-generator is not installed or failed to execute."; \
			echo "Please visit https://openapi-generator.tech/docs/installation/ for installation instructions."; \
			exit 1; \
		}

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

