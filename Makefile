
BINARY_NAME=vlan-scout
default: ${BINARY_NAME}
SOURCES := $(shell find . -type f -name "*.go")

RELEASE_DEPS = fmt lint
include release.mk

# ldflags are linker flags. The -X flag allows us to set the value of a
# string variable in the target package at build time.
# Here we set the `version` variable in the `main` package.
LDFLAGS := -ldflags="-X main.version=${VERSION}"

${BINARY_NAME}: ${SOURCES} go.mod go.sum
	@echo "Building $@ with version: ${VERSION}"
	go build ${LDFLAGS} -o $@ .

.PHONY: clean
clean:
	rm -rf ${BINARY_NAME} dist/ .libs/

.PHONY: setup-build-deps
setup-build-deps:
	./scripts/setup-build-deps.sh

.PHONY: goreleaser
goreleaser: lint setup-build-deps
	goreleaser release --snapshot --clean

.PHONY: update-deps
update-deps:
	go get -u
	go mod tidy

.PHONY: deps
deps: go.mod
	GOPROXY=direct go mod download
	GOPROXY=direct go get -u all

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test ./...

fmt:
	go fmt ./...