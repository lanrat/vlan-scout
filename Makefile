BINARY_NAME=vlan-scout

# Get the current version from git.
# `git describe` will use the most recent tag.
# `--tags` ensures any tag is considered, not just annotated ones.
# `--always` ensures that if no tags are present, the commit hash is used.
# `--dirty` will append "-dirty" if the working directory has uncommitted changes.
VERSION := $(shell git describe --tags --always --dirty)

# ldflags are linker flags. The -X flag allows us to set the value of a
# string variable in the target package at build time.
# Here we set the `version` variable in the `main` package.
LDFLAGS := -ldflags="-X main.version=${VERSION}"

default: build

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

.PHONY: release
release: docker-builder lint
	docker run --rm \
		-v `pwd`:/go/src/ \
		-w /go/src/ \
		-e CGO_ENABLED=1 \
		builder release --snapshot --clean

.PHONY: release-gh
release-gh: docker-builder
	docker run --rm \
		-v `pwd`:/go/src/ \
		-w /go/src/ \
		-e CGO_ENABLED=1 \
		-e GITHUB_TOKEN=${GITHUB_TOKEN} \
		builder release --clean

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

# Release target to create a new semantic version tag
.PHONY: release-tag
release-tag: lint
    # This shell 'if' statement runs at execution time, not parse time.
	@if [ -z "$(BUMP)" ]; then \
		echo "Error: BUMP is not set. Usage: make release BUMP=patch|minor|major"; \
		exit 1; \
	fi

    # 1. Check for a clean working directory
	@if ! git diff --quiet; then \
		echo "Error: Working directory is not clean. Commit or stash changes before releasing."; \
		exit 1; \
	fi

    # 2. Get the latest git tag, or start at v0.0.0
	@CURRENT_TAG=$$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"); \
	CURRENT_VERSION=$$(echo $$CURRENT_TAG | sed 's/^v//'); \
	MAJOR=$$(echo $$CURRENT_VERSION | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT_VERSION | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT_VERSION | cut -d. -f3); \
	\
	if [ "$(BUMP)" = "patch" ]; then \
		PATCH=$$((PATCH + 1)); \
	elif [ "$(BUMP)" = "minor" ]; then \
		MINOR=$$((MINOR + 1)); \
		PATCH=0; \
	elif [ "$(BUMP)" = "major" ]; then \
		MAJOR=$$((MAJOR + 1)); \
		MINOR=0; \
		PATCH=0; \
	else \
		echo "Error: Invalid BUMP value. Use 'patch', 'minor', or 'major'."; \
		exit 1; \
	fi; \
	\
	NEW_TAG="v$${MAJOR}.$${MINOR}.$${PATCH}"; \
	echo "Current version: $$CURRENT_TAG"; \
	echo "Creating new version: $$NEW_TAG"; \
	git tag $$NEW_TAG; \
	git push origin $$NEW_TAG;