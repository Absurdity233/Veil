#!/usr/bin/env node
/**
 * A tiny static server for development.
 *
 * The web client has one hard requirement that a plain file:// page cannot
 * meet: crypto.getRandomValues is disabled on an insecure origin, so the page
 * has to be served over http://localhost or https. `npx serve` would also work;
 * this exists so the repo has no narrative dependency on a tool that might be
 * pulled.
 *
 * It is a development server, not a deployment story: no TLS, no caching
 * headers, no index fallback beyond the obvious.
 */

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "public");
const port = Number(process.env.PORT ?? 5173);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  let path = normalize(decodeURIComponent(url.pathname));

  // One directory only, and never above it. A development server that can read
  // outside its root is how a demo becomes an incident.
  if (path.includes("..")) {
    res.writeHead(403).end("forbidden");
    return;
  }

  let file = join(root, path === "/" ? "index.html" : path);

  try {
    const info = await stat(file);
    if (info.isDirectory()) file = join(file, "index.html");
  } catch {
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    return;
  }

  try {
    const body = await readFile(file);
    res.writeHead(200, {
      "content-type": MIME[extname(file)] ?? "application/octet-stream",
      // The wasm module is fetched as an ES module import; both need the
      // application/wasm type and a same-origin policy relaxed enough for the
      // relay websocket.
      "cross-origin-embedder-policy": "require-corp",
      "cross-origin-opener-policy": "same-origin",
    });
    res.end(body);
  } catch (e) {
    res.writeHead(500, { "content-type": "text/plain" }).end(`error: ${e.message}`);
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`veil web on http://127.0.0.1:${port}`);
  console.log("the relay must allow this origin if it is not the default:");
  console.log(`  VEIL_ALLOWED_ORIGINS=http://127.0.0.1:${port}`);
});