/**
 * Which conversation the transcript is showing.
 *
 * Its own module rather than part of main.ts, for one practical reason: main.ts
 * touches the DOM at module level, so nothing in it can be imported by a test in
 * Node. This is the one piece of the client's UI state with a failure mode that
 * is *silent* — a value of the wrong shape selects a conversation that does not
 * exist, and the transcript then shows nothing with no explanation — so it is
 * the piece worth testing.
 */

export type Selection =
  | { kind: "peer"; id: string }
  | { kind: "group"; id: string };

/**
 * Parses a stored selection.
 *
 * A bare string is accepted as a peer id: that is what older builds stored, and
 * keeping it working is what makes an upgrade preserve the conversation the user
 * was reading rather than dropping them at an empty pane.
 *
 * Anything else malformed — empty, truncated JSON, a kind that is not one of the
 * two, a non-string id — returns null, which means "nothing selected". Selecting
 * nothing is a state the UI already handles correctly.
 */
export function parseSelection(raw: string | null): Selection | null {
  if (raw === null || raw.length === 0) return null;

  // Two storage formats are in the wild: an older build wrote a bare peer id, and
  // the current one writes JSON. Telling them apart has to be done by *trying*,
  // because a peer id is opaque - it may start with a brace, a digit, anything.
  //
  // So the parse is attempted first, and only a value that parses is examined:
  //   - parses to an object  -> read kind and id, reject anything malformed
  //   - parses to a scalar   -> "null", "42", '"x"': corrupt, since no build
  //                             ever stored one as a bare string
  //   - does not parse      -> an older build's bare id
  //
  // The one case this cannot distinguish is a peer literally named "null" or a
  // 4-byte id that happens to be valid JSON. Both would have to have been stored
  // by a build that wrote a bare string, so accepting them as ids would be wrong
  // too; a corrupt value selecting nothing is the safer reading.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Not JSON. A string that *looks* like the start of a JSON object or array
    // is a truncated or corrupted stored value rather than a peer id: no peer id
    // in this system begins with a brace, because ids are names people type.
    const looksTruncated = raw.startsWith("{") || raw.startsWith("[");
    return looksTruncated ? null : { kind: "peer", id: raw };
  }

  if (parsed === null || typeof parsed !== "object") return null;

  const candidate = parsed as { kind?: unknown; id?: unknown };
  if (candidate.kind !== "peer" && candidate.kind !== "group") return null;
  if (typeof candidate.id !== "string" || candidate.id.length === 0) return null;

  return { kind: candidate.kind, id: candidate.id };
}

/** The form written to storage. Kept beside the parser so they cannot drift. */
export function encodeSelection(selection: Selection): string {
  return JSON.stringify(selection);
}