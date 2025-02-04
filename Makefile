IGNORED_PATH := "internal/dependencytrack/client"
GO_PACKAGES := $(shell go list ./... | grep -v $(IGNORED_PATH))

build:
	go build -o bin/api ./cmd/api

fmt:
	@echo "Running go fmt..."
	go fmt $(GO_PACKAGES)

test:
	go test -cover ./...

check: vulncheck deadcode gosec staticcheck

staticcheck:
	@echo "Running staticcheck..."
	go run honnef.co/go/tools/cmd/staticcheck@latest $(GO_PACKAGES)

vulncheck:
	@echo "Running vulncheck..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

deadcode:
	@echo "Running deadcode..."
	go run golang.org/x/tools/cmd/deadcode@latest -filter "pkg/api/vulnerabilities/options" -test ./...

gosec:
	@echo "Running gosec..."
	go run github.com/securego/gosec/v2/cmd/gosec@latest --exclude G404,G101 --exclude-generated -terse ./...

generate: generate-proto generate_dp_track generate-sql generate-mocks

generate-proto:
	protoc \
		-I pkg/api/vulnerabilities/schema/ \
		./pkg/api/vulnerabilities/schema/*.proto \
		--go_out=. \
		--go-grpc_out=.

generate_dp_track:
	@echo "Generating Go code from the OpenAPI specification..."
	@openapi-generator generate \
        -i schema/dtrack.json \
        -g go \
        -o internal/dependencytrack/client \
        --global-property apiTests=false,modelTests=false \
        --package-name client \
        --additional-properties=withGoMod=false \
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
