import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type {
  FileReseal,
  PullRequest,
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
  body: {
    path: string;
    key: string;
    value: string;
    /** Limits the seal to the file's documents in these regions. */
    regions?: string[];
  },
): Promise<Seal> {
  const { data } = await apiClient.post<Seal>(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}/seals`,
    body,
  );
  return data;
}

/**
 * Reseals every value of a file's documents for the env that is on an
 * older key: the results become pending changes. Values with a pending
 * change in the session are left alone. The control plane refuses (409)
 * with a sentence when it cannot.
 */
export async function requestReseal(
  owner: string,
  repo: string,
  sessionId: string,
  path: string,
): Promise<FileReseal> {
  const { data } = await apiClient.post<FileReseal>(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}/reseals`,
    { path },
  );
  return data;
}

/** A file reseal's progress. */
export async function getReseal(
  owner: string,
  repo: string,
  sessionId: string,
  resealId: string,
): Promise<FileReseal> {
  const { data } = await apiClient.get<FileReseal>(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}/reseals/${encodeURIComponent(resealId)}`,
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

/**
 * Opens a pull request with the session's pending changes. The session ends
 * once it is open.
 */
export async function openPullRequest(
  owner: string,
  repo: string,
  sessionId: string,
): Promise<PullRequest> {
  const { data } = await apiClient.post<{ pull_request: PullRequest }>(
    `${repoPath(owner, repo)}/session/${encodeURIComponent(sessionId)}/pull-request`,
  );
  return data.pull_request;
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
