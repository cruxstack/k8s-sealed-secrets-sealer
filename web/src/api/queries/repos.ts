import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type { FileListing, RepositoryList } from "@/api/types";

/**
 * The repositories the GitHub App is installed on. A list can cost the
 * control plane a GitHub call per repository, so returning to the tab does
 * not fetch it again.
 */
export const reposQueryOptions = queryOptions({
  queryKey: ["repos"],
  queryFn: async () => {
    const { data } = await apiClient.get<RepositoryList>("/repos");
    return data;
  },
  staleTime: 60_000,
  refetchOnWindowFocus: false,
});

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
