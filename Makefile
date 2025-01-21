IGNORED_PATH := "internal/dependencytrack/client"
GO_PACKAGES := $(shell go list ./... | grep -v $(IGNORED_PATH))

build:
	go build -o bin/api ./cmd/api

fmt:
	go run mvdan.cc/gofumpt@latest -w ./

test:
	go test -cover --race ./...

check: staticcheck vulncheck deadcode gosec

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

generate: generate-proto generate_dp_track

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
