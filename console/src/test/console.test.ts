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
