generate-proto:
	protoc \
		-I pkg/api/vulnerabilities/schema/ \
		./pkg/api/vulnerabilities/schema/*.proto \
		--go_out=. \
		--go-grpc_out=.

build:
	go build -o bin/api ./cmd/api

fmt: prettier
	go run mvdan.cc/gofumpt@latest -w ./

