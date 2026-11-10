import type { RepositoryFile } from "@/api/types";
import { safeHttpUrl } from "@/lib/utils";

/**
 * A file's hints, from its documents' optional annotations: what the secret
 * is for, a link to its docs, and the keys it should hold. A file's
 * documents usually share them; the first one given wins.
 */
export interface FileHints {
  description?: string;
  docs?: string;
  /** Every expected key, in the order the documents give them. */
  expected: string[];
}

export function fileHints(file: RepositoryFile): FileHints {
  const docs = file.documents ?? [];
  const expected: string[] = [];
  for (const d of docs) {
    for (const k of d.expected_keys ?? []) {
      if (!expected.includes(k)) expected.push(k);
    }
  }
  return {
    description: docs.find((d) => d.description)?.description,
    docs: safeHttpUrl(docs.find((d) => d.docs)?.docs) ?? undefined,
    expected,
  };
}

/**
 * The expected keys some document of the file still lacks, counting values
 * waiting in the session as there.
 */
export function missingKeys(
  file: RepositoryFile,
  pending: ReadonlySet<string>,
): string[] {
  const missing: string[] = [];
  for (const d of file.documents ?? []) {
    for (const k of d.expected_keys ?? []) {
      if (!d.keys.includes(k) && !pending.has(k) && !missing.includes(k)) {
        missing.push(k);
      }
    }
  }
  return missing;
}
