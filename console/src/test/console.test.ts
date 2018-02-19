/**
 * Tests for the console modules, using the Node.js built-in test runner
 * (`node:test`) and `node:assert` — no third-party test framework.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { parseLine, parseAuditLog } from "../audit.js";
import { aggregate, filterEvents } from "../report.js";
import { parsePolicy, globMatch } from "../policy.js";
