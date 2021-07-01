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
