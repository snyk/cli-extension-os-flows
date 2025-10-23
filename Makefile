## Include per-checkout configuration
#
# local.mk is a way to override settings on a per-checkout basis.  It is in the
# .gitignore and shouldn't be committed to git.
-include local.mk

# Project-specific overrides can go here.  Make sure to use ?= for assignment,
# though; otherwise you may overwrite a value from local.mk.  Using ?= in a
# Makefile means that the variable should only be set if it is not already set.
#
######################################################
### BEGIN PROJECT-SPECIFIC CONFIGURATION OVERRIDES ###
######################################################

# Define GOCI_LINT_V for golangci-lint. The install.sh script handles OS/ARCH.
# User requested v1.64.6 for local macOS use.
GOCI_LINT_V?=v1.64.6
# Define GOTESTSUM_V for gotestsum. The install.sh script handles OS/ARCH.
GOTESTSUM_V?=1.13.0

####################################################
### END PROJECT-SPECIFIC CONFIGURATION OVERRIDES ###
####################################################

# Variables
ARCH?=$(shell go env GOARCH)
GO_BIN?=$(shell pwd)/.bin
OS?=$(shell go env GOOS)

# Update PATH for make targets
SHELL:=env PATH=$(GO_BIN):$(PATH) $(SHELL)

.PHONY: all
all: install-tools lint-go ## Install tools and run linters

.PHONY: install-tools
install-tools: install-oapi-codegen install-tsp ## Install golangci-lint and other tools for local development
	mkdir -p ${GO_BIN}
ifndef CI
	@echo "Installing golangci-lint ${GOCI_LINT_V} to ${GO_BIN}..."
	curl -sSfL 'https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh' | sh -s -- -b ${GO_BIN} ${GOCI_LINT_V}
	@echo "golangci-lint installed."
	@echo "Installing gotestsum ${GOTESTSUM_V} to ${GO_BIN}..."
	curl -sSfL 'https://github.com/gotestyourself/gotestsum/releases/download/v${GOTESTSUM_V}/gotestsum_${GOTESTSUM_V}_${OS}_${ARCH}.tar.gz' | tar -xz -C ${GO_BIN} gotestsum
	@echo "gotestsum installed."
else
	@echo "CI environment detected, skipping local installation of golangci-lint."
endif

.PHONY: install-oapi-codegen
install-oapi-codegen: .bin/go/oapi-codegen

.bin/go/oapi-codegen:
	GOBIN=$(shell pwd)/.bin/go go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.3.0

.PHONY: install-tsp
install-tsp:
	npm install -D @typespec/compiler @typespec/openapi3

.PHONY: lint
lint: lint-go ## Run all linters (currently only golangci-lint)

.PHONY: lint-go
lint-go: ## Run golangci linters
ifdef CI
	mkdir -p test/results
	golangci-lint run --out-format junit-xml ./... > test/results/lint-tests.xml
else
	golangci-lint run -v ./...
endif

.PHONY: test
test:
	mkdir -p test/results
	gotestsum --junitfile test/results/unit-tests.xml -- -race -v ./...

.PHONY: format
format: format-tsp format-go

.PHONY: format-tsp
format-tsp:
	./node_modules/.bin/tsp format 'internal/definitions/**/*.tsp'

.PHONY: format-go
format-go:
	golangci-lint run --fix -v ./...

.PHONY: generate
generate: tsp-compile oapi-generate

.PHONY: tsp-compile oapi-generate
tsp-compile:
	./node_modules/.bin/tsp compile internal/legacy/definitions/main.tsp

.PHONY: oapi-generate
oapi-generate:
	PATH=$(shell pwd)/.bin/go:$(PATH) go generate ./internal/...

.PHONY: clean
clean: ## Clean up the .bin directory
	@echo "Cleaning up .bin directory..."
	rm -rf $(GO_BIN)

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
