import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type { SealingStatus } from "@/api/types";

/** Whether values can be sealed in the env right now, for everyone. */
export const statusQueryOptions = queryOptions({
  queryKey: ["status"],
  queryFn: async () => {
    const { data } = await apiClient.get<SealingStatus>("/status");
    return data;
  },
  refetchInterval: 30_000,
  staleTime: 10_000,
});
