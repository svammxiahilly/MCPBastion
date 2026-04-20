# mcp-bastion-console

The TypeScript component of [MCP Bastion](../README.md): a **dependency-free**
(Node standard library only) viewer for audit logs and policies.

The only `devDependencies` are `typescript` and `@types/node` — both used at
build time to compile the sources. Nothing is required at runtime.

## Build & test

```sh
npm install       # installs the build-time devDependencies
npm run build     # tsc -> dist/
npm test          # node --test over compiled tests
npm run typecheck # tsc --noEmit
```

## Usage

```sh
node dist/cli.js report <audit.jsonl> [--json] [--decision D] [--tool S]
node dist/cli.js tail   <audit.jsonl> [--decision D]
node dist/cli.js policy <policy-file>
```

- **report** — aggregate an audit log: decision counts, per-tool activity,
  redaction tallies, byte totals. Cross-checks the gateway's own summary line
  and exits non-zero on mismatch. `--json` emits a machine-readable object;
  `--decision`/`--tool` add a filtered event listing.
- **tail** — one compact line per event, optionally filtered by decision.
- **policy** — parse, summarise and lint a policy file. Exits non-zero if the
  policy has errors (unknown directives, non-integer limits, …).

`D` is one of `forward`, `deny`, `drop`, `error`.

## Modules

| Module      | Responsibility                                   |
|-------------|--------------------------------------------------|
| `audit.ts`  | Audit JSONL schema + defensive parser.           |
| `report.ts` | Pure aggregation and filtering.                  |
| `policy.ts` | Read-only policy parser, linter and glob matcher.|
| `render.ts` | Plain-text and JSON rendering.                   |
| `cli.ts`    | Command-line entry point.                        |
