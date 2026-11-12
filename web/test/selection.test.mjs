// The stored conversation selection.
//
// This is the one piece of the web client's UI state with a failure mode that is
// silent: a value of the wrong shape selects a conversation that does not exist,
// and the transcript pane then shows nothing with no explanation. Everything
// else in main.ts is DOM wiring that a browser test would cover; this is the part
// worth pinning in Node.
//
// Imported from dist/ rather than src/: Node cannot run TypeScript, and the same
// rule the other suites follow is that the test exercises what ships.

import assert from "node:assert/strict";
import test from "node:test";

import { encodeSelection, parseSelection } from "../dist/selection.js";

test("a peer selection round-trips", () => {
  const selection = { kind: "peer", id: "alice" };
  assert.deepEqual(parseSelection(encodeSelection(selection)), selection);
});

test("a group selection round-trips", () => {
  const selection = { kind: "group", id: "team" };
  assert.deepEqual(parseSelection(encodeSelection(selection)), selection);
});

test("a bare id from an older build is read as a peer", () => {
  // Upgrading must not drop the user at an empty pane because the stored shape
  // changed. A bare string is what the previous version wrote.
  assert.deepEqual(parseSelection("alice"), { kind: "peer", id: "alice" });
});

test("nothing stored means nothing selected", () => {
  assert.equal(parseSelection(null), null);
  assert.equal(parseSelection(""), null);
});

test("malformed values select nothing rather than something wrong", () => {
  const cases = [
    "{",                                   // truncated JSON
    "null",                                // parsed, but not an object
    "[]",                                  // an array is not a selection
    '{"kind":"peer"}',                     // no id
    '{"id":"alice"}',                      // no kind
    '{"kind":"channel","id":"x"}',         // a kind the UI does not have
    '{"kind":"peer","id":""}',             // an empty id
    '{"kind":"peer","id":42}',             // an id that is not a string
  ];

  for (const raw of cases) {
    assert.equal(parseSelection(raw), null, `expected null for ${raw}`);
  }
});

test("a group whose id looks like a peer id stays a group", () => {
  // The kind travels with the id precisely so this cannot be misread: an id is
  // opaque, and nothing about its shape says which kind of conversation it names.
  const selection = { kind: "group", id: "alice" };
  assert.deepEqual(parseSelection(encodeSelection(selection)), selection);
});