BIN := hs
CARGO := cargo

.PHONY: all build release test clippy fmt fmt-check doc doc-open doc-watch audit run install clean help

all: build

build: ## Build the debug binary
	$(CARGO) build

release: ## Build the release binary
	$(CARGO) build --release

test: ## Run the test suite
	$(CARGO) test

clippy: ## Run clippy with warnings denied
	$(CARGO) clippy --all-targets -- -D warnings

fmt: ## Format the code in place
	$(CARGO) fmt

fmt-check: ## Check formatting without modifying files
	$(CARGO) fmt --check

doc: ## Build the documentation (HTML) into target/doc
	$(CARGO) doc --no-deps

doc-open: ## Open the generated documentation in a browser
	$(CARGO) doc --no-deps --open

doc-watch: ## Watch for changes and rebuild the documentation
	$(CARGO) doc --no-deps --watch

audit: ## Audit dependencies for known vulnerabilities
	$(CARGO) audit

run: build ## Run the compiled binary
	./target/debug/$(BIN)

install: ## Install the binary to Cargo's bin directory
	$(CARGO) install --path .

clean: ## Remove build artifacts
	$(CARGO) clean

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}' | sort
