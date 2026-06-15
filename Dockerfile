FROM cgr.dev/chainguard/go:latest AS builder
ENV GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE=on
WORKDIR /src
COPY go.mod go.sum ./
COPY pkg/api/go.mod pkg/api/go.sum ./pkg/api/
RUN go mod download
COPY . .
RUN go build -o /bin/api cmd/api/main.go

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /bin/api /api
ENTRYPOINT ["/api"]
