local: build
	docker compose up -d
	./bin/api

build:
	mise run build:api

build-cli:
	mise run build:cli

install-cli:
	go -C ./pkg/cli build -o ${GOBIN}/vulnz

tidy:
	@echo "Running go mod tidy for all modules..."
	find . -name go.mod -execdir go mod tidy \;

test-all:  test test-integration

test:
	mise run test

test-integration:
	go test -count=1 ./... -tags integration_test -run TestUpdater

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

check: vet fmt vulncheck deadcode staticcheck goimport helm-lint gofix

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
	mise run check:staticcheck

# -exclude=GO-2025-3770 Several
# Sigstore-related modules (e.g., cosign, rekor, sigstore-go, timestamp-authority) are pulling in the vulnerable version
# Ignore until we can update to a version that is not vulnerable
vulncheck:
	mise run check:govulncheck

deadcode:
	mise run check:deadcode

# Is not in the total check, error for pkg/cli
gosec:
	mise run check:gosec

gofix:
	mise run check:gofix

helm-lint:
	@echo "Running helm lint..."
	helm lint --strict ./charts

generate: generate-proto generate-sql generate-mocks

generate-proto:
	mise run generate:proto

generate-sql:
	mise run generate:sqlc

generate-mocks:
	mise run generate:mocks

refresh-db:
	docker compose down -v

TENANT ?= nav
connect-db:
	mise run db:proxy ${TENANT}
