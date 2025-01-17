generate-proto:
	protoc \
		-I pkg/api/vulnerabilities/schema/ \
		./pkg/api/vulnerabilities/schema/*.proto \
		--go_out=. \
		--go-grpc_out=.

build:
	go build -o bin/api ./cmd/api

fmt:
	go run mvdan.cc/gofumpt@latest -w ./

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
