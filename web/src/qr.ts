/**
 * QR codes, for the device linking flow.
 *
 * A thin wrapper over `qrcode` rather than a hand-written encoder.
 *
 * That choice was made the hard way: a hand-rolled encoder produced codes whose
 * finder patterns and module counts were provably correct and which no decoder
 * could read. QR is a pipeline of bit packing, Reed-Solomon, block interleaving,
 * zig-zag placement, masking and BCH format bits, and a mistake in any one of
 * them yields a well-formed square that scans as noise. The library is a
 * generation-only dependency - no network, no decoding, ~40 KB - which is a
 * smaller risk than a subtly wrong bridge for a feature whose entire purpose is
 * to be trusted.
 *
 * Scope kept deliberately narrow: byte mode, error correction level L (the code
 * is shown on a screen at close range, not printed and smudged), and a hard
 * failure rather than a truncation when the payload does not fit.
 */

import QRCode from "qrcode";

/** A rendered QR code: a square matrix of modules. */
export interface QrCode {
  size: number;
  version: number;
  /** Row-major, one byte per module; 1 = dark. */
  modules: Uint8Array;
}

/**
 * Encodes bytes as a QR code.
 *
 * Throws when the payload does not fit. Chosen over truncating because a code
 * that lost its last bytes cannot be adopted, and the failure would be invisible:
 * the scanner would report a correctly-read code with a corrupt credential.
 */
export function encodeQr(data: Uint8Array): QrCode {
  // `qrcode` takes a string or a byte buffer. A Uint8Array is passed through as
  // bytes, which is what byte mode needs: a linking request is binary with
  // length prefixes, not text.
  const qr = QRCode.create([{ data, mode: "byte" }], {
    errorCorrectionLevel: "L",
  });

  const size = qr.modules.size;
  const modules = new Uint8Array(size * size);

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      modules[y * size + x] = qr.modules.get(y, x) ? 1 : 0;
    }
  }

  return { size, version: qr.version, modules };
}

/** Renders a QR code onto a canvas 2D context. */
export function drawQr(
  ctx: CanvasRenderingContext2D,
  code: QrCode,
  options: { scale?: number; margin?: number; dark?: string; light?: string } = {},
): void {
  const scale = options.scale ?? 5;
  const margin = options.margin ?? 4;
  const full = (code.size + margin * 2) * scale;

  ctx.fillStyle = options.light ?? "#ffffff";
  ctx.fillRect(0, 0, full, full);
  ctx.fillStyle = options.dark ?? "#000000";

  for (let y = 0; y < code.size; y++) {
    for (let x = 0; x < code.size; x++) {
      if (code.modules[y * code.size + x] === 1) {
        ctx.fillRect((x + margin) * scale, (y + margin) * scale, scale, scale);
      }
    }
  }
}
