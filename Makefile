# MCP Bastion — top-level Makefile
#
# Orchestrates the Rust gateway and the TypeScript console. Every target is a
# thin wrapper around cargo / npm so behaviour is identical in CI and locally.

GATEWAY := gateway
CONSOLE := console
POLICY  := policies/default.policy
SESSION := sessions/demo-session.jsonl

.PHONY: all build test lint fmt gateway-build gateway-test gateway-lint \
        console-build console-test demo clean help

all: build test ## Build and test everything

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: gateway-build console-build ## Build both components

test: gateway-test console-test ## Test both components

lint: gateway-lint ## Lint the Rust gateway (clippy)

fmt: ## Format the Rust sources
	cd $(GATEWAY) && cargo fmt

# ---- Rust gateway ----------------------------------------------------------

gateway-build: ## Build the gateway (release)
	cd $(GATEWAY) && cargo build --release

