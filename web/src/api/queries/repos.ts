import { queryOptions } from "@tanstack/react-query";
import apiClient, { toApiError } from "@/api/client";
import type { FileListing, RepositoryList } from "@/api/types";
import { useAuth } from "@/lib/auth";
import { useEnv } from "@/lib/env";
import {
  clearRepoCache,
  readRepoCache,
  writeRepoCache,
  type RepoCacheScope,
  type SavedRepoList,
} from "@/lib/repo-cache";

/**
 * The repositories the GitHub App is installed on that the user can read.
 * A list can cost the control plane a GitHub call per repository, so
 * returning to the tab does not fetch it again.
 *
 * With a scope (the signed-in user in the page's env), the list this
 * browser saved last shows at once, as of when it was saved: it counts as
 * stale, so the server's list is fetched straight away and replaces it
 * when it comes. The list is saved when it arrives, in the fetch itself
 * rather than by a page, so a list that arrives after the user moved on
 * (to a repository picked from the saved one) is saved all the same; the
 * request takes no abort signal, so leaving the page doesn't cancel it.
 */
export function reposQueryOptions(scope: RepoCacheScope | null) {
  // read once, for both the list and its time
  let saved: SavedRepoList | null | undefined;
  const read = () => (saved ??= scope ? readRepoCache(scope) : null);
  return queryOptions({
    queryKey: ["repos"],
    queryFn: async () => {
      try {
        const { data } = await apiClient.get<RepositoryList>("/repos");
        if (scope) writeRepoCache(scope, data);
        return data;
      } catch (err) {
        // a list the server refuses this user is not shown again
        if (scope && toApiError(err).status === 403) clearRepoCache(scope);
        throw err;
      }
    },
    initialData: () => read()?.list,
    initialDataUpdatedAt: () => read()?.at,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

/** The repository list's options for the signed-in user in this env. */
export function useReposQueryOptions() {
  const user = useAuth().user?.id;
  const env = useEnv()?.name;
  return reposQueryOptions(user !== undefined && env ? { user, env } : null);
}

/**
 * A repository's SealedSecret files at `commit` (a session's base), or at
 * the head of its default branch when commit is undefined. A commit never
 * changes, so its listing is never fetched again while it is cached; a
 * listing can cost the control plane hundreds of GitHub calls.
 */
export function repoFilesQueryOptions(
  owner: string,
  repo: string,
  commit?: string,
) {
  return queryOptions({
    queryKey: ["repos", owner, repo, "files", commit ?? "head"],
    queryFn: async () => {
      const { data } = await apiClient.get<FileListing>(
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/files`,
        { params: commit ? { commit } : undefined },
      );
      return data;
    },
    staleTime: commit ? Infinity : 30_000,
    refetchOnWindowFocus: !commit,
    // switching from the head to a session's base keeps showing the same
    // repository's files, never another repository's
    placeholderData: (previous) =>
      previous?.repository.full_name.toLowerCase() ===
      `${owner}/${repo}`.toLowerCase()
        ? previous
        : undefined,
  });
}
