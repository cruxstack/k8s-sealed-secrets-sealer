import type {
  PendingChange,
  RepositoryFile,
  SealedSecretDocument,
} from "@/api/types";
import { fileHints } from "./hints";

/**
 * Names regions for people: "use1", "use1 and use2", "use1, use2 and use3".
 * Documents without a region are "no region".
 */
export function regionList(regions: readonly string[]): string {
  const names = regions.map((r) => r || "no region");
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/**
 * Names a document within its file for people: its namespace and name, and
 * its region when it has one, since copies of a secret in several regions
 * often share a namespace and name.
 */
export function docId(d: {
  namespace: string;
  name: string;
  region?: string;
}): string {
  const id = `${d.namespace}/${d.name}`;
  return d.region ? `${id} in ${d.region}` : id;
}

interface DocRef {
  index?: number;
  namespace: string;
  name: string;
  region?: string;
}

/**
 * Identifies a document within its file by its position, as changes record
 * it; changes stored before they did name it by region, namespace and name.
 */
function docRef(d: DocRef): string {
  return d.index === undefined ? byName(d) : `#${d.index}`;
}

function byName(d: DocRef): string {
  return `${d.region ?? ""}/${d.namespace}/${d.name}`;
}

/**
 * The documents of a file with a value waiting in the session, per key:
 * each change names the documents it still sets.
 */
export type PendingDocs = ReadonlyMap<string, ReadonlySet<string>>;

export const NO_PENDING: PendingDocs = new Map();

/** A session's pending documents per key, for one file. */
export function pendingDocs(
  changes: readonly PendingChange[],
  path: string,
): PendingDocs {
  const out = new Map<string, Set<string>>();
  for (const c of changes) {
    if (c.path !== path) continue;
    const docs = out.get(c.key) ?? new Set<string>();
    for (const t of c.targets) docs.add(docRef(t));
    out.set(c.key, docs);
  }
  return out;
}

/** Whether a value for key waits in the session for the document. */
export function isPending(
  pending: PendingDocs,
  key: string,
  d: SealedSecretDocument,
): boolean {
  const docs = pending.get(key);
  return !!docs && (docs.has(docRef(d)) || docs.has(byName(d)));
}

/**
 * Where a key stands in one document:
 * - `set`: the document holds it;
 * - `pending`: a value for it waits in the session;
 * - `lacking`: the document should hold it and doesn't: its hints name the
 *   key, or it has no hints to say otherwise;
 * - `unneeded`: the document's hints don't name it, so it isn't missed.
 */
export type DocKeyState = "set" | "pending" | "lacking" | "unneeded";

export function docKeyState(
  d: SealedSecretDocument,
  key: string,
  pending: PendingDocs,
): DocKeyState {
  if (isPending(pending, key, d)) return "pending";
  if (d.keys.includes(key)) return "set";
  const expected = d.expected_keys ?? [];
  return expected.length === 0 || expected.includes(key)
    ? "lacking"
    : "unneeded";
}

/**
 * Where a key stands across a file's documents:
 * - `set`: every document that needs it holds it;
 * - `partial`: some hold it or have it pending, and others lack it;
 * - `missing`: it is needed, but no document holds it or has it pending;
 * - `new`: a value waits in the session, and no document holds it yet;
 * - `replaced`: a value waits in the session, replacing the file's.
 */
export type KeyState = "set" | "partial" | "missing" | "new" | "replaced";

/** Where a key stands in one region's documents. */
export type RegionKeyState =
  "set" | "pending" | "partial" | "missing" | "unneeded";

export interface RegionStatus {
  /** The region, or "" for documents without one. */
  region: string;
  state: RegionKeyState;
  /** How many documents the region has in the file. */
  docs: number;
}

export interface KeyStatus {
  key: string;
  state: KeyState;
  /** Whether the file's hints name it. */
  expected: boolean;
  /** How many documents hold it. */
  holders: number;
  /** How many documents have a value for it pending. */
  pending: number;
  /** How many documents need it: those whose hints don't leave it out. */
  needed: number;
  /** The documents that lack it, as `docId` names them. */
  lacking: string[];
  /**
   * Where it stands per region, when the file's documents are in more than
   * one; empty otherwise.
   */
  regions: RegionStatus[];
}

/**
 * The regions of a file's documents, in order of first appearance, with ""
 * for documents without one. Empty when they are all in one region or none,
 * so there is nothing to choose between.
 */
export function fileRegions(file: RepositoryFile): string[] {
  const regions: string[] = [];
  for (const d of file.documents ?? []) {
    const r = d.region ?? "";
    if (!regions.includes(r)) regions.push(r);
  }
  return regions.filter((r) => r !== "").length >= 2 ? regions : [];
}

function regionState(states: DocKeyState[]): RegionKeyState {
  const has = (s: DocKeyState) => states.includes(s);
  if (has("lacking")) {
    return has("set") || has("pending") ? "partial" : "missing";
  }
  if (has("pending")) return "pending";
  if (has("set")) return "set";
  return "unneeded";
}

/**
 * Every key of a file worth showing: the keys its hints expect, in their
 * order, then the rest it holds or has pending, by name.
 */
export function keyStatuses(
  file: RepositoryFile,
  pending: PendingDocs,
): KeyStatus[] {
  const docs = file.documents ?? [];
  const { expected } = fileHints(file);
  const regions = fileRegions(file);
  const others = [
    ...new Set([...docs.flatMap((d) => d.keys), ...pending.keys()]),
  ].filter((k) => !expected.includes(k));
  others.sort();
  return [...expected, ...others].map((key) => {
    const states = docs.map((d) => docKeyState(d, key, pending));
    const count = (s: DocKeyState) => states.filter((x) => x === s).length;
    const holders = docs.filter((d) => d.keys.includes(key)).length;
    const waiting = count("pending");
    const lacking = docs
      .filter((_, i) => states[i] === "lacking")
      .map((d) => docId(d));
    const state: KeyState =
      lacking.length === 0
        ? waiting > 0
          ? holders > 0
            ? "replaced"
            : "new"
          : "set"
        : holders > 0 || waiting > 0
          ? "partial"
          : "missing";
    return {
      key,
      state,
      expected: expected.includes(key),
      holders,
      pending: waiting,
      needed: states.filter((s) => s !== "unneeded").length,
      lacking,
      regions: regions.map((region) => {
        const inRegion = docs
          .map((d, i) => ((d.region ?? "") === region ? states[i] : null))
          .filter((s): s is DocKeyState => s !== null);
        return {
          region,
          state: regionState(inRegion),
          docs: inRegion.length,
        };
      }),
    };
  });
}

/**
 * The keys some document of the file needs and lacks, counting values
 * waiting in the session as there.
 */
export function missingKeys(
  file: RepositoryFile,
  pending: PendingDocs,
): string[] {
  const missing: string[] = [];
  for (const d of file.documents ?? []) {
    for (const k of d.expected_keys ?? []) {
      if (!missing.includes(k) && docKeyState(d, k, pending) === "lacking") {
        missing.push(k);
      }
    }
  }
  return missing;
}
