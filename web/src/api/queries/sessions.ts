import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type {
  Seal,
  SealSession,
  SessionList,
  SessionResponse,
} from "@/api/types";

const repoPath = (owner: string, repo: string) =>
  `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

export const sessionsQueryOptions = queryOptions({
  queryKey: ["sessions"],
  queryFn: async () => {
    const { data } = await apiClient.get<SessionList>("/sessions");
    return data.sessions;
  },
  staleTime: 30_000,
});

export function sessionQueryKey(owner: string, repo: string) {
  return ["repos", owner, repo, "session"] as const;
}

/** The user's open session for a repository, or null. */
export function sessionQueryOptions(owner: string, repo: string) {
  return queryOptions({
    queryKey: sessionQueryKey(owner, repo),
    queryFn: async () => {
      const { data } = await apiClient.get<SessionResponse>(
        `${repoPath(owner, repo)}/session`,
      );
      return data.session;
    },
    staleTime: 30_000,
  });
}

/** A seal's progress. */
export async function getSeal(
  owner: string,
  repo: string,
  sessionId: string,
  sealId: string,
): Promise<Seal> {
  const { data } = await apiClient.get<Seal>(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}/seals/${encodeURIComponent(sealId)}`,
  );
  return data;
}

/**
 * Opens a session at `commit`, the head the user is looking at, or returns
 * their open one.
 */
export async function openSession(
  owner: string,
  repo: string,
  commit: string,
): Promise<SealSession> {
  const { data } = await apiClient.post<{ session: SealSession }>(
    `${repoPath(owner, repo)}/session`,
    { commit },
  );
  return data.session;
}

/**
 * Asks for a value to be sealed into every document of a file. The value is
 * sent once and never kept by the client after the request.
 */
export async function requestSeal(
  owner: string,
  repo: string,
  sessionId: string,
  body: { path: string; key: string; value: string },
): Promise<Seal> {
  const { data } = await apiClient.post<Seal>(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}/seals`,
    body,
  );
  return data;
}

export async function discardSession(
  owner: string,
  repo: string,
  sessionId: string,
): Promise<void> {
  await apiClient.delete(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}`,
  );
}

export async function removeChange(
  owner: string,
  repo: string,
  sessionId: string,
  changeId: string,
): Promise<void> {
  await apiClient.delete(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}/changes/${encodeURIComponent(changeId)}`,
  );
}
