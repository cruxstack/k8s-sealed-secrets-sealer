import { useCallback, useMemo, useSyncExternalStore } from "react";
import type { Repository } from "@/api/types";
import { useAuth } from "@/lib/auth";
import { useEnv } from "@/lib/env";

/**
 * A repository the user sealed a value into, as this browser remembers it.
 * Only names and a time are kept: never a key or a value.
 */
export interface RecentRepo {
  /** owner/name, as the page the seal was made on spelled it. */
  repository: string;
  /** The file the last value went into. */
  path?: string;
  /** When, as an ISO time. */
  sealed_at: string;
}

/** How many repositories are remembered per user and env. */
export const MAX_RECENT = 12;

/** Told when this tab remembers a seal; other tabs get a storage event. */
const CHANGED = "sealer:recent-repos";

function storageKey(login: string, env: string): string {
  return `sealer.recent-repos:${login}:${env}`;
}

/** The remembered repositories in raw, newest first; bad entries dropped. */
function parse(raw: string | null): RecentRepo[] {
  if (!raw) return [];
  let list: unknown;
  try {
    list = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(list)) return [];
  return list.filter(
    (r): r is RecentRepo =>
      typeof r === "object" &&
      r !== null &&
      typeof r.repository === "string" &&
      r.repository.includes("/") &&
      typeof r.sealed_at === "string" &&
      !Number.isNaN(Date.parse(r.sealed_at)) &&
      (r.path === undefined || typeof r.path === "string"),
  );
}

function read(key: string): string | null {
  // storage can be missing or refused (a private window, blocked site
  // data): nothing is remembered then, and the page works the same
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/**
 * Remembers that the user sealed a value into a repository's file, making
 * it the most recent.
 */
export function rememberSeal(
  login: string,
  env: string,
  repository: string,
  path: string,
  at: Date = new Date(),
): void {
  if (!login || !env) return;
  const key = storageKey(login, env);
  const name = repository.toLowerCase();
  const list = parse(read(key)).filter(
    (r) => r.repository.toLowerCase() !== name,
  );
  list.unshift({ repository, path, sealed_at: at.toISOString() });
  try {
    localStorage.setItem(key, JSON.stringify(list.slice(0, MAX_RECENT)));
  } catch {
    return;
  }
  window.dispatchEvent(new Event(CHANGED));
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener(CHANGED, onChange);
  window.addEventListener("storage", onChange);
  return () => {
    window.removeEventListener(CHANGED, onChange);
    window.removeEventListener("storage", onChange);
  };
}

/**
 * The repositories the signed-in user sealed values into in the current
 * env, newest first, as this browser remembers them.
 */
export function useRecentRepos(): RecentRepo[] {
  const login = useAuth().user?.login ?? "";
  const env = useEnv()?.name ?? "";
  const key = login && env ? storageKey(login, env) : "";
  // the raw string is the snapshot: it compares equal until it changes
  const raw = useSyncExternalStore(
    subscribe,
    () => (key ? read(key) : null),
    () => null,
  );
  return useMemo(() => parse(raw), [raw]);
}

/** Remembers a seal for the signed-in user in the current env. */
export function useRememberSeal(): (repository: string, path: string) => void {
  const login = useAuth().user?.login ?? "";
  const env = useEnv()?.name ?? "";
  return useCallback(
    (repository: string, path: string) =>
      rememberSeal(login, env, repository, path),
    [login, env],
  );
}

/** How many recent repositories show above the list. */
const RECENT_SHOWN = 6;

export interface RecentItem {
  repo: Repository;
  /** Pending changes in its open session. */
  pending: number;
  /** When the user last sealed into it, from this browser. */
  sealedAt?: string;
  /** The file they sealed into then. */
  path?: string;
}

/**
 * The repositories to pick up first: those with pending changes, then
 * those the user sealed into lately (as this browser remembers), newest
 * first. Only repositories in the list show, so one the user can no
 * longer read is left out.
 */
export function recentItems(
  repos: Repository[],
  pending: Map<string, number>,
  recent: RecentRepo[],
): RecentItem[] {
  const byName = new Map(repos.map((r) => [r.full_name.toLowerCase(), r]));
  const sealed = new Map(recent.map((r) => [r.repository.toLowerCase(), r]));
  const items: RecentItem[] = [];
  const add = (name: string) => {
    const repo = byName.get(name);
    if (!repo || items.some((i) => i.repo === repo)) return;
    const last = sealed.get(name);
    items.push({
      repo,
      pending: pending.get(name) ?? 0,
      sealedAt: last?.sealed_at,
      path: last?.path,
    });
  };
  const time = (name: string) =>
    Date.parse(sealed.get(name)?.sealed_at ?? "") || 0;
  // work waiting for a pull request first, the latest sealed into first
  [...pending.keys()]
    .filter((name) => (pending.get(name) ?? 0) > 0)
    .sort((a, b) => time(b) - time(a))
    .forEach(add);
  recent.forEach((r) => add(r.repository.toLowerCase()));
  return items.slice(0, RECENT_SHOWN);
}
