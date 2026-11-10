import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type { FileListing, RepositoryList } from "@/api/types";

export const reposQueryOptions = queryOptions({
  queryKey: ["repos"],
  queryFn: async () => {
    const { data } = await apiClient.get<RepositoryList>("/repos");
    return data.repositories;
  },
  staleTime: 60_000,
});

/**
 * A repository's SealedSecret files at `commit` (a session's base), or at
 * the head of its default branch when commit is undefined.
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
    staleTime: 30_000,
    // switching from the head to a session's base keeps showing the same
    // repository's files, never another repository's
    placeholderData: (previous) =>
      previous?.repository.full_name.toLowerCase() ===
      `${owner}/${repo}`.toLowerCase()
        ? previous
        : undefined,
  });
}
