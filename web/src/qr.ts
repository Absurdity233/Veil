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

// ---- Scanning ----------------------------------------------------------
//
// Two paths, because no single one works everywhere:
//
//   - `BarcodeDetector` is native and fast, and exists on Chrome/Edge and recent
//     Android browsers. It is tried first.
//   - otherwise the `jsqr` decoder runs on frames pulled from a canvas. It is a
//     devDependency today and is bundled here, which costs about 40 KB for the
//     browsers that need it.
//
// Camera access requires a secure origin, which the deployment already is - over
// http the browser refuses `getUserMedia` for the same reason it refuses
// `crypto.subtle`, and the caller reports that rather than showing a black box.

/** What a scan attempt produced. */
export type ScanResult =
  | { ok: true; text: string }
  | { ok: false; reason: string };

interface ScannerHandle {
  stop(): void;
}

/**
 * Starts scanning from the device camera into `video`.
 *
 * Resolves once the camera is running; `onCode` is called with the first decoded
 * payload and the scanner then stops itself. Rejects when the camera is
 * unavailable, so the caller can fall back to typing the request.
 */
export async function startScanning(
  video: HTMLVideoElement,
  onCode: (text: string) => void,
): Promise<ScannerHandle> {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error(
      "this browser has no camera access; serve the page over https and try again",
    );
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "environment" },
    audio: false,
  });

  video.srcObject = stream;
  video.setAttribute("playsinline", "true");
  await video.play().catch(() => {
    // Autoplay can be refused; the frames still arrive once the user taps play,
    // so this is not fatal.
  });

  let stopped = false;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    for (const track of stream.getTracks()) track.stop();
    video.srcObject = null;
  };

  // Native path.
  const Detector = (globalThis as { BarcodeDetector?: new (opts: { formats: string[] }) => {
    detect(source: CanvasImageSource): Promise<Array<{ rawValue: string }>>;
  } }).BarcodeDetector;

  if (Detector) {
    const detector = new Detector({ formats: ["qr_code"] });
    const tick = async () => {
      if (stopped) return;
      try {
        const found = await detector.detect(video);
        if (found.length > 0 && found[0]?.rawValue) {
          onCode(found[0].rawValue);
          stop();
          return;
        }
      } catch {
        // A transient decode failure is normal while the camera focuses.
      }
      if (!stopped) requestAnimationFrame(() => void tick());
    };
    // The first frames are usually too early: the camera has not exposed one yet.
    setTimeout(() => void tick(), 250);

    return { stop };
  }

  // Fallback: pull frames into a canvas and decode them.
  const { default: jsQR } = await import("jsqr");
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) {
    stop();
    throw new Error("this browser cannot decode images");
  }

  const tick = () => {
    if (stopped) return;

    if (video.readyState >= video.HAVE_CURRENT_DATA) {
      const width = video.videoWidth;
      const height = video.videoHeight;
      if (width > 0 && height > 0) {
        // Downscale: a 4K frame is slower to decode and buys nothing, since a
        // QR at typical screen distance is well above the decoder's minimum.
        const scale = Math.min(1, 640 / Math.max(width, height));
        canvas.width = Math.round(width * scale);
        canvas.height = Math.round(height * scale);

        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const decoded = jsQR(image.data, canvas.width, canvas.height);

        if (decoded?.data) {
          onCode(decoded.data);
          stop();
          return;
        }
      }
    }

    if (!stopped) setTimeout(tick, 120);
  };
  setTimeout(tick, 250);

  return { stop };
}

/** Whether this browser can scan at all, for a UI that should not offer it otherwise. */
export function canScan(): boolean {
  return typeof navigator !== "undefined" &&
    typeof navigator.mediaDevices?.getUserMedia === "function";
}
