import type { RepositoryFile } from "@/api/types";
import { fileHints } from "./hints";

/**
 * Where a key of a file stands across the file's documents:
 * - `set`: every document holds it;
 * - `partial`: some documents hold it and others don't;
 * - `missing`: it is expected, but no document holds it;
 * - `new`: a value waits in the session, and no document holds it yet;
 * - `replaced`: a value waits in the session, replacing the file's.
 */
export type KeyState = "set" | "partial" | "missing" | "new" | "replaced";

export interface KeyStatus {
  key: string;
  state: KeyState;
  /** Whether the file's hints name it. */
  expected: boolean;
  /** How many documents hold it. */
  holders: number;
  /** The documents without it, as namespace/name. */
  lacking: string[];
}

/**
 * Every key of a file worth showing: the keys its hints expect, in their
 * order, then the rest it holds or has pending, by name. A pending value is
 * sealed for every document, so it settles the key whatever the documents
 * hold now.
 */
export function keyStatuses(
  file: RepositoryFile,
  pending: ReadonlySet<string>,
): KeyStatus[] {
  const docs = file.documents ?? [];
  const { expected } = fileHints(file);
  const others = [
    ...new Set([...docs.flatMap((d) => d.keys), ...pending]),
  ].filter((k) => !expected.includes(k));
  others.sort();
  return [...expected, ...others].map((key) => {
    const without = docs.filter((d) => !d.keys.includes(key));
    const holders = docs.length - without.length;
    const state: KeyState = pending.has(key)
      ? holders > 0
        ? "replaced"
        : "new"
      : holders === 0
        ? "missing"
        : without.length > 0
          ? "partial"
          : "set";
    return {
      key,
      state,
      expected: expected.includes(key),
      holders,
      lacking: without.map((d) => `${d.namespace}/${d.name}`),
    };
  });
}
