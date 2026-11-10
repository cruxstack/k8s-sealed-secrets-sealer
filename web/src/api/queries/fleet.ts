import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type { Fleet, KeyStatus } from "@/api/types";

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

/**
 * A fingerprint as a URL path segment: its base64 in the URL-safe alphabet,
 * as the control plane expects.
 */
export function fingerprintPath(fingerprint: string): string {
  return encodeURIComponent(
    fingerprint.replace(/\+/g, "-").replace(/\//g, "_"),
  );
}

/**
 * Revokes a key: the control plane stops using it (never the env key, never
 * restored, never missing). Clusters keep it.
 */
export async function revokeKey(fingerprint: string): Promise<KeyStatus> {
  const { data } = await apiClient.post<KeyStatus>(
    `/keys/${fingerprintPath(fingerprint)}/revoke`,
  );
  return data;
}

/** Reinstates a revoked key. */
export async function reinstateKey(fingerprint: string): Promise<KeyStatus> {
  const { data } = await apiClient.post<KeyStatus>(
    `/keys/${fingerprintPath(fingerprint)}/reinstate`,
  );
  return data;
}
