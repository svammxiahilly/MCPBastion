# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private
[security advisory](https://github.com/svammxiahilly/MCPBastion/security/advisories/new) form, or contact a
maintainer directly if the form is unavailable to you.

Include what an attacker gains in one sentence, the version or commit you are running, the smallest
reproduction you can manage, and whether the input is attacker-controlled in your setup. You should
get an acknowledgement within a few working days and a disclosure timeline before anything is
published.

## Scope

MCPBastion gates JSON-RPC between an MCP client and server. In scope: crafted
JSON-RPC (deep nesting, huge lines, unicode) that slips past a matcher, a policy rule
that fails open, an audit line that disagrees with what was forwarded, and path
handling in the console renderer.
