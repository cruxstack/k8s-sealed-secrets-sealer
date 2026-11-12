import type { Repository, RepositoryList } from "@/api/types";
import { forgetRecentRepos } from "@/lib/recent-repos";
import { removeByPrefix } from "@/lib/storage";

/**
 * Whose list a saved entry is: a GitHub user, by the numeric id a renamed
 * login keeps, in one env.
 */
export interface RepoCacheScope {
  user: number;
  env: string;
}

/** A list saved in this browser, and when the server sent it. */
export interface SavedRepoList {
  list: RepositoryList;
  /** When it was saved, in milliseconds since the epoch. */
  at: number;
}

const PREFIX = "sealer.repos.v1:";

/** How long a saved list is shown; an older one is dropped unread. */
export const REPO_CACHE_MAX_AGE_MS = 14 * 24 * 3_600_000;

/** How far ahead of this clock a saved time may be, for a clock that moved. */
const CLOCK_SKEW_MS = 5 * 60_000;

function storageKey(scope: RepoCacheScope): string {
  return `${PREFIX}${scope.user}:${scope.env}`;
}

/**
 * A repository as the list shows it, and nothing more: a stored entry is
 * not trusted, so anything else in it is dropped, and an entry that is not
 * a repository is refused.
 */
function repository(r: unknown): Repository | null {
  if (typeof r !== "object" || r === null) return null;
  const v = r as Record<string, unknown>;
  if (
    typeof v.owner !== "string" ||
    typeof v.name !== "string" ||
    typeof v.full_name !== "string" ||
    v.full_name !== `${v.owner}/${v.name}` ||
    typeof v.private !== "boolean" ||
    typeof v.default_branch !== "string" ||
    (v.access !== "read" && v.access !== "write")
  ) {
    return null;
  }
  return {
    owner: v.owner,
    name: v.name,
    full_name: v.full_name,
    private: v.private,
    default_branch: v.default_branch,
    access: v.access,
  };
}

function list(raw: unknown): RepositoryList | null {
  if (typeof raw !== "object" || raw === null) return null;
  const v = raw as Record<string, unknown>;
  if (!Array.isArray(v.repositories)) return null;
  const repositories: Repository[] = [];
  for (const r of v.repositories) {
    const repo = repository(r);
    if (!repo) return null;
    repositories.push(repo);
  }
  return v.incomplete === true
    ? { repositories, incomplete: true }
    : { repositories };
}

/**
 * The list saved for a user in an env, or null when there is none, it is
 * too old, or it cannot be read. Storage can be missing or refused (a
 * private window, blocked site data); the page works the same without it.
 */
export function readRepoCache(
  scope: RepoCacheScope,
  now: number = Date.now(),
): SavedRepoList | null {
  let raw: string | null;
  try {
    raw = localStorage.getItem(storageKey(scope));
  } catch {
    return null;
  }
  if (!raw) return null;
  let entry: unknown;
  try {
    entry = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof entry !== "object" || entry === null) return null;
  const e = entry as Record<string, unknown>;
  const at = e.at;
  if (
    e.v !== 1 ||
    typeof at !== "number" ||
    !Number.isFinite(at) ||
    at > now + CLOCK_SKEW_MS ||
    now - at > REPO_CACHE_MAX_AGE_MS
  ) {
    return null;
  }
  const saved = list(e.list);
  return saved ? { list: saved, at } : null;
}

/** Saves the list the server sent, replacing the one saved before. */
export function writeRepoCache(
  scope: RepoCacheScope,
  repos: RepositoryList,
  now: number = Date.now(),
): void {
  const saved = list(repos);
  if (!saved) return;
  try {
    localStorage.setItem(
      storageKey(scope),
      JSON.stringify({ v: 1, at: now, list: saved }),
    );
  } catch {
    // full or refused storage: the next visit fetches the list as before
  }
}

/** Drops the list saved for a user in an env. */
export function clearRepoCache(scope: RepoCacheScope): void {
  try {
    localStorage.removeItem(storageKey(scope));
  } catch {
    // nothing to drop when storage can't be used
  }
}

/**
 * Signing out leaves nothing of anyone's in this browser: every saved
 * repository list and every list of recent repositories goes. The theme,
 * which is no one's, stays.
 */
export function forgetBrowserData(): void {
  removeByPrefix(PREFIX);
  forgetRecentRepos();
}
