// QR round trip against an independent decoder.
//
// This is the test that matters. A QR encoder can produce something whose finder
// patterns, module counts and format bits are all provably correct and which no
// scanner can read - which is exactly what the first, hand-written version of
// this did. Only a decoder confirms the whole pipeline.
//
// jsQR is a test-only reference implementation. It is not shipped to the page.

import assert from "node:assert/strict";
import test from "node:test";

import jsQR from "jsqr";

import { encodeQr } from "../dist/qr.js";

/**
 * Rasterises a code to RGBA with a quiet zone, as a screen would show it.
 *
 * The loops run over pixels, not modules: iterating modules and writing a
 * `scale`-sized block inside them double-counts the scaling, which produces a
 * raster that looks plausible and decodes to nothing. That mistake cost an hour
 * of blaming the encoder when the encoder was right.
 */
function rasterise(code, scale = 4, margin = 4) {
  const full = (code.size + margin * 2) * scale;
  const rgba = new Uint8ClampedArray(full * full * 4);

  for (let py = 0; py < full; py++) {
    for (let px = 0; px < full; px++) {
      const mx = Math.floor(px / scale) - margin;
      const my = Math.floor(py / scale) - margin;

      const inside = mx >= 0 && my >= 0 && mx < code.size && my < code.size;
      const dark = inside && code.modules[my * code.size + mx] === 1;

      const at = (py * full + px) * 4;
      const value = dark ? 0 : 255;
      rgba[at] = value;
      rgba[at + 1] = value;
      rgba[at + 2] = value;
      rgba[at + 3] = 255;
    }
  }

  return { rgba, width: full, height: full };
}

function roundTrip(bytes) {
  const code = encodeQr(bytes);
  const { rgba, width, height } = rasterise(code);
  return { code, decoded: jsQR(rgba, width, height) };
}

test("a short payload decodes back to itself", () => {
  const { decoded } = roundTrip(new TextEncoder().encode("VEILINV1hello"));

  assert.ok(decoded, "a decoder must find a code in the raster");
  assert.equal(decoded.data, "VEILINV1hello");
});

test("a linking-request-sized payload decodes", () => {
  // The real case: a base64 linking request is around 200 bytes. If this fails
  // the feature does not work, however correct the structure looks.
  const payload = new TextEncoder().encode(
    Array.from({ length: 200 }, (_, i) => String.fromCharCode(65 + (i % 26))).join(""),
  );
  const { code, decoded } = roundTrip(payload);

  assert.ok(decoded, `no code found in a version ${code.version} raster`);
  assert.equal(decoded.data, new TextDecoder().decode(payload));
});

test("payloads across the size range decode", () => {
  // Sizes that land on different block layouts, so a layout mistake is caught.
  for (const size of [1, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271]) {
    const payload = Uint8Array.from({ length: size }, (_, i) =>
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/".charCodeAt(i % 38));
    const { decoded } = roundTrip(payload);

    assert.ok(decoded, `a ${size}-byte payload did not decode`);
    assert.equal(decoded.data.length, size, `a ${size}-byte payload decoded short`);
  }
});

test("a payload that does not fit raises rather than truncating", () => {
  // A code that lost its last bytes would scan as a correctly-read corrupt
  // credential, and the failure would be attributed to the credential.
  assert.throws(() => encodeQr(new Uint8Array(3000)));
});

test("the same input produces the same modules", () => {
  // Determinism matters because the code is compared visually: two renders of one
  // request must be identical, or the user will think it changed.
  const data = new TextEncoder().encode("VEILINV1same");
  assert.deepEqual(Array.from(encodeQr(data).modules), Array.from(encodeQr(data).modules));
});

test("different input produces different modules", () => {
  const a = encodeQr(new TextEncoder().encode("VEILINV1one"));
  const b = encodeQr(new TextEncoder().encode("VEILINV1two"));
  assert.notDeepEqual(Array.from(a.modules), Array.from(b.modules));
});