# Hullcloak Development Justfile

default:
    @just --list

# Build hc binary
build:
    @mkdir -p bin
    go build -o bin/hc ./cmd/hc
    @echo "Built: bin/hc"

# Run all tests
test:
    go test -race ./...

# Run tests verbose
test-v:
    go test -race -v ./...

# Run network smoke tests (requires internet)
test-smoke:
    HC_SMOKE_NET=1 go test -race -v ./internal/exec/

# Lint code
lint:
    golangci-lint run ./...

# Format code
fmt:
    go fmt ./...
    gofmt -s -w .

# Tidy dependencies
tidy:
    go mod tidy

# Vet code
vet:
    go vet ./...

# Run all checks
check: fmt tidy vet lint test
    @echo "All checks passed"

# Clean build artifacts
clean:
    rm -rf bin/

# Local dev workflow
dev: fmt tidy lint test
    @echo "Dev checks passed"
