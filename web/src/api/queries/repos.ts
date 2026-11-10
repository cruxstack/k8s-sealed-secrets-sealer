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

export function repoFilesQueryOptions(owner: string, repo: string) {
  return queryOptions({
    queryKey: ["repos", owner, repo, "files"],
    queryFn: async () => {
      const { data } = await apiClient.get<FileListing>(
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/files`,
      );
      return data;
    },
    staleTime: 30_000,
  });
}
