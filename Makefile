
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
	rm -rf ${BINARY_NAME} dist/

.PHONY: docker-builder
docker-builder:
	docker build -t builder builder/

.PHONY: goreleaser
goreleaser: docker-builder lint
	docker run --rm \
		--user $(shell id -u):$(shell id -g) \
		-v $(CURDIR):/go/src/ \
		-w /go/src/ \
		-e HOME=/tmp \
		builder release --snapshot --clean

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