#!/usr/bin/env node
/**
 * Rebuilds the WebAssembly module from the C++ source.
 *
 * The engine is the same code the phone runs; this script is the whole
 * platform-specific part of the web build. It exists as a script rather than a
 * CMake target because the Emscripten toolchain on Windows is easier to drive
 * directly than through CMake's toolchain files, and because the flags below are
 * the interesting part — a CMake wrapper would just hide them.
 *
 * Requires an activated emsdk (emcc on PATH). On a machine without one, the
 * checked-in .wasm is what the page uses; this is for changing the engine.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const web = join(here, "..");
const root = join(web, "..");
const cpp = join(root, "core-native", "src", "main", "cpp");
const out = join(web, "public", "wasm");

/** The ABI plus the allocator. Nothing else is reachable from JavaScript. */
const EXPORTED = [
  "_veil_engine_new", "_veil_engine_restore", "_veil_engine_free",
  "_veil_identity_secrets", "_veil_identity_public", "_veil_identity_binding",
  "_veil_sign_challenge",
  "_veil_rotate_prekeys", "_veil_export_prekey_set", "_veil_needs_prekey_refill",
  "_veil_export_prekey_state", "_veil_import_prekey_state",
  "_veil_measure_session", "_veil_measure_prekey_state", "_veil_measure_peer_registry",
  "_veil_establish_outbound", "_veil_session_state",
  "_veil_export_session", "_veil_import_session", "_veil_drop_session",
  "_veil_peer_identity", "_veil_export_peer_registry", "_veil_import_peer_registry",
  "_veil_encrypt", "_veil_decrypt", "_veil_safety_number",
  "_veil_set_random_source", "_veil_version",
  "_veil_install_web_rng", "_veil_web_rng_ready",
  // Multi-device.
  "_veil_init_device", "_veil_device_id", "_veil_device_credential",
  "_veil_adopt_device_credential", "_veil_adopt_device_list",
  "_veil_peer_devices", "_veil_peer_device_version", "_veil_device_fingerprint",
  "_veil_establish_with_devices", "_veil_encrypt_to_account",
  "_malloc", "_free",
];

const cxxSources = [
  "veil/veil_c.cpp", "veil/crypto.cpp", "veil/keys.cpp", "veil/random.cpp",
  "veil/ratchet.cpp", "veil/engine.cpp", "wasm/rng_bridge.cpp",
].map((p) => join(cpp, p));

const cSources = [
  "third_party/monocypher/monocypher.c",
  "third_party/monocypher/monocypher-ed25519.c",
].map((p) => join(cpp, p));

function run(cmd, args) {
  console.log(`${cmd} ${args.join(" ")}`);
  execFileSync(cmd, args, { stdio: "inherit", shell: process.platform === "win32" });
}

if (!existsSync(join(cpp, "veil", "veil_c.cpp"))) {
  console.error("cannot find the engine sources at", cpp);
  process.exit(1);
}

mkdirSync(out, { recursive: true });
const objDir = join(web, "build", "wasm-obj");
mkdirSync(objDir, { recursive: true });

const common = ["-O2", "-w", `-I${cpp}`, `-I${join(cpp, "third_party", "monocypher")}`];

// C first: emcc refuses -std=c++17 for a .c file, so the two languages cannot
// share one invocation.
const cObjects = [];
for (const src of cSources) {
  const obj = join(objDir, `${src.split(/[\\/]/).pop()}.o`);
  run("emcc", [...common, "-c", src, "-o", obj]);
  cObjects.push(obj);
}

run("em++", [
  ...common,
  "-std=c++17",
  // The engine is written without exceptions and without RTTI, so the wasm
  // build matches the phone's build rather than accidentally growing features
  // the C++ never uses.
  "-fno-exceptions",
  "-fno-rtti",
  "-sMODULARIZE=1",
  "-sEXPORT_ES6=1",
  "-sEXPORT_NAME=createVeilModule",
  // No Node path: this module is for a page and a worker. Shipping the Node
  // shims would be dead weight in every download.
  "-sENVIRONMENT=web,worker",
  "-sALLOW_MEMORY_GROWTH=1",
  "-sINITIAL_MEMORY=16777216",
  "-sFILESYSTEM=0",
  "-sNO_EXIT_RUNTIME=1",
  `-sEXPORTED_FUNCTIONS=${JSON.stringify(EXPORTED)}`,
  ...cxxSources,
  ...cObjects,
  "-o", join(out, "veil.js"),
]);

console.log(`\nwrote ${join(out, "veil.js")} and veil.wasm`);