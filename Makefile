# MCP Bastion — top-level Makefile
#
# Orchestrates the Rust gateway and the TypeScript console. Every target is a
# thin wrapper around cargo / npm so behaviour is identical in CI and locally.

GATEWAY := gateway
