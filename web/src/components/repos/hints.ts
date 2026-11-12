import type { RepositoryFile } from "@/api/types";
import { safeHttpUrl } from "@/lib/utils";

/**
 * A file's hints, from its documents' optional annotations: a short name
 * for the secret, what it is for, a link to its docs, the keys it should
 * hold, and where it goes in the file list. A file's documents usually
 * share them; the first one given wins.
 */
export interface FileHints {
  title?: string;
  description?: string;
  docs?: string;
  /** Every expected key, in the order the documents give them. */
  expected: string[];
  /** Where it goes in the file list: 0 first, then up. */
  order?: number;
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
    order: docs.find((d) => d.order !== undefined)?.order,
  };
}

/**
 * Files in the order the file list shows them: those with an order hint
 * first, lowest first, then the rest. Files that tie keep the order they
 * came in (the server's, by path).
 */
export function sortFiles(files: RepositoryFile[]): RepositoryFile[] {
  const rank = (f: RepositoryFile) => fileHints(f).order ?? Infinity;
  // sort is stable: ties keep their places
  return [...files].sort((a, b) => {
    const [x, y] = [rank(a), rank(b)];
    return x === y ? 0 : x < y ? -1 : 1;
  });
}
