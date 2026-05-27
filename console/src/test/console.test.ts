/**
 * Tests for the console modules, using the Node.js built-in test runner
 * (`node:test`) and `node:assert` — no third-party test framework.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { parseLine, parseAuditLog } from "../audit.js";
import { aggregate, filterEvents } from "../report.js";
import { parsePolicy, globMatch } from "../policy.js";
import { renderReport, renderPolicy } from "../render.js";

const SAMPLE = [
  '{"ts_ms":4,"seq":1,"decision":"forward","reason":"allow_tool read_file","method":"tools/call","tool":"read_file","id":"1","bytes_in":110,"bytes_out":110,"redacted":[],"balanced":true,"max_depth":3}',
  '{"ts_ms":4,"seq":2,"decision":"forward","reason":"allow_tool list_dir","method":"tools/call","tool":"list_dir","id":"2","bytes_in":141,"bytes_out":132,"redacted":["api_key"],"balanced":true,"max_depth":3}',
  '{"ts_ms":4,"seq":3,"decision":"deny","reason":"deny_tool shell.*","method":"tools/call","tool":"shell.exec","id":"3","bytes_in":108,"bytes_out":0,"redacted":[],"balanced":true,"max_depth":3}',
  '{"summary":true,"total":3,"forward":2,"deny":1,"drop":0,"error":0}',
].join("\n");

test("parseLine parses a valid event", () => {
  const r = parseLine(SAMPLE.split("\n")[0]!, 1);
  assert.equal(r.kind, "event");
  if (r.kind === "event") {
    assert.equal(r.event.decision, "forward");
    assert.equal(r.event.tool, "read_file");
    assert.equal(r.event.bytesIn, 110);
  }
});

test("parseLine parses the summary line", () => {
  const r = parseLine('{"summary":true,"total":3,"forward":2,"deny":1,"drop":0,"error":0}', 1);
  assert.equal(r.kind, "summary");
  if (r.kind === "summary") assert.equal(r.summary.total, 3);
});

test("parseLine reports invalid JSON as error", () => {
  const r = parseLine("{not json", 5);
  assert.equal(r.kind, "error");
  if (r.kind === "error") assert.equal(r.line, 5);
});

test("parseLine rejects wrong field type", () => {
  const r = parseLine('{"ts_ms":"x","seq":1,"decision":"forward","reason":"r","method":null,"tool":null,"id":null,"bytes_in":0,"bytes_out":0,"redacted":[],"balanced":true,"max_depth":0}', 1);
  assert.equal(r.kind, "error");
});

test("parseLine rejects invalid decision", () => {
  const r = parseLine('{"ts_ms":1,"seq":1,"decision":"nope","reason":"r","method":null,"tool":null,"id":null,"bytes_in":0,"bytes_out":0,"redacted":[],"balanced":true,"max_depth":0}', 1);
  assert.equal(r.kind, "error");
});

test("parseAuditLog collects events and summary", () => {
  const rep = parseAuditLog(SAMPLE);
  assert.equal(rep.events.length, 3);
  assert.ok(rep.summary);
  assert.equal(rep.errors.length, 0);
});

test("aggregate computes decision counts and byte totals", () => {
  const rep = parseAuditLog(SAMPLE);
  const agg = aggregate(rep);
  assert.equal(agg.total, 3);
  assert.equal(agg.counts.forward, 2);
  assert.equal(agg.counts.deny, 1);
  assert.equal(agg.bytesIn, 110 + 141 + 108);
  assert.equal(agg.redactionEvents, 1);
  assert.equal(agg.redactedKeyCounts.get("api_key"), 1);
  assert.equal(agg.summaryMatches, true);
});

test("aggregate detects summary mismatch", () => {
  const bad = SAMPLE.replace('"forward":2', '"forward":99');
  const agg = aggregate(parseAuditLog(bad));
  assert.equal(agg.summaryMatches, false);
});

test("aggregate builds per-tool stats sorted by total", () => {
  const rep = parseAuditLog(SAMPLE);
  const agg = aggregate(rep);
  const tools = agg.tools.map((t) => t.tool);
  assert.deepEqual(new Set(tools), new Set(["read_file", "list_dir", "shell.exec"]));
  const shell = agg.tools.find((t) => t.tool === "shell.exec")!;
  assert.equal(shell.denied, 1);
});

test("filterEvents narrows by decision and tool", () => {
  const rep = parseAuditLog(SAMPLE);
  assert.equal(filterEvents(rep.events, { decision: "deny" }).length, 1);
  assert.equal(filterEvents(rep.events, { tool: "read" }).length, 1);
  assert.equal(filterEvents(rep.events, { decision: "forward", tool: "list" }).length, 1);
});

test("renderReport produces a stable header and counts", () => {
  const out = renderReport(aggregate(parseAuditLog(SAMPLE)));
  assert.ok(out.includes("MCP Bastion — Audit Report"));
  assert.ok(out.includes("Total messages : 3"));
  assert.ok(out.includes("forward"));
  assert.ok(out.includes("read_file"));
});

test("parsePolicy reads directives and defaults", () => {
  const text = [
    "default = deny",
    "allow_tool = read_file",
    "deny_tool = shell.*",
    "redact_arg = *token*",
    "max_bytes = 1024",
    "rate_limit = 5",
    'redaction_mask = "***"',
  ].join("\n");
  const { policy, issues } = parsePolicy(text);
  assert.equal(policy.defaultAllow, false);
  assert.deepEqual(policy.allowTools, ["read_file"]);
  assert.deepEqual(policy.denyTools, ["shell.*"]);
  assert.equal(policy.maxBytes, 1024);
  assert.equal(policy.rateLimit, 5);
  assert.equal(policy.redactionMask, "***");
  assert.equal(issues.filter((i) => i.severity === "error").length, 0);
});

test("parsePolicy flags unknown directive", () => {
  const { issues } = parsePolicy("wat = 1\n");
  assert.ok(issues.some((i) => i.severity === "error" && i.message.includes("unknown directive")));
});

test("parsePolicy warns on shadowed allow", () => {
  const { issues } = parsePolicy("allow_tool = shell.exec\ndeny_tool = shell.*\n");
  assert.ok(issues.some((i) => i.severity === "warning" && i.message.includes("shadowed")));
});

test("parsePolicy rejects non-integer limit", () => {
  const { issues } = parsePolicy("max_bytes = big\n");
  assert.ok(issues.some((i) => i.message.includes("max_bytes must be an integer")));
});

test("globMatch mirrors the Rust matcher", () => {
  assert.equal(globMatch("read_file", "read_file"), true);
  assert.equal(globMatch("shell.*", "shell.exec"), true);
  assert.equal(globMatch("*password*", "db_password"), true);
  assert.equal(globMatch("*_token", "auth_token"), true);
  assert.equal(globMatch("*_token", "token_x"), false);
  assert.equal(globMatch("read_file", "read_files"), false);
});

test("renderPolicy lists tools and lint results", () => {
  const { policy, issues } = parsePolicy("default = deny\nallow_tool = read_file\n");
  const out = renderPolicy(policy, issues);
  assert.ok(out.includes("Default decision : DENY"));
  assert.ok(out.includes("+ read_file"));
});
