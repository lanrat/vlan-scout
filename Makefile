
BINARY_NAME=vlan-scout

default: build

RELEASE_DEPS = fmt lint
include release.mk

# ldflags are linker flags. The -X flag allows us to set the value of a
# string variable in the target package at build time.
# Here we set the `version` variable in the `main` package.
LDFLAGS := -ldflags="-X main.version=${VERSION}"

.PHONY: build
build:
	@echo "Building ${BINARY_NAME} with version: ${VERSION}"
	go build ${LDFLAGS} -o ${BINARY_NAME} .

.PHONY: clean
clean:
	rm -f ${BINARY_NAME}

.PHONY: docker-builder
docker-builder:
	docker build -t builder builder/

.PHONY: goreleaser
goreleaser: docker-builder lint
	docker run --rm \
		-v `pwd`:/go/src/ \
		-w /go/src/ \
		-e CGO_ENABLED=1 \
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