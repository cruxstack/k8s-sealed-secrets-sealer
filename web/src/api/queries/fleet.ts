import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type { Fleet } from "@/api/types";

/** How often the fleet view refreshes; agents check in every 15 seconds. */
export const FLEET_REFRESH_MS = 15_000;

export const fleetQueryOptions = queryOptions({
  queryKey: ["fleet"],
  queryFn: async () => {
    const { data } = await apiClient.get<Fleet>("/fleet");
    return data;
  },
  refetchInterval: FLEET_REFRESH_MS,
  staleTime: 5_000,
});
