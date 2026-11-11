import type { RepositoryFile } from "@/api/types";
import { safeHttpUrl } from "@/lib/utils";

/**
 * A file's hints, from its documents' optional annotations: a short name
 * for the secret, what it is for, a link to its docs, and the keys it
 * should hold. A file's documents usually share them; the first one given
 * wins.
 */
export interface FileHints {
  title?: string;
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
    title: docs.find((d) => d.title)?.title,
    description: docs.find((d) => d.description)?.description,
    docs: safeHttpUrl(docs.find((d) => d.docs)?.docs) ?? undefined,
    expected,
  };
}
