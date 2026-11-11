import { queryOptions } from "@tanstack/react-query";
import apiClient, { ApiError } from "@/api/client";
import type { SetupForm, SetupStatus } from "@/api/types";

/**
 * The GitHub App setup, or null once the App is set up: the control plane
 * serves the setup API only until then, and answers 404 after.
 */
export const setupStatusQueryOptions = queryOptions({
  queryKey: ["setup"],
  queryFn: async (): Promise<SetupStatus | null> => {
    try {
      const { data } = await apiClient.get<SetupStatus>("/setup");
      return data;
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return null;
      throw err;
    }
  },
  retry: false,
});

/** Starts creating the App: the form to post to GitHub. */
export async function startSetup(): Promise<SetupForm> {
  const { data } = await apiClient.post<SetupForm>("/setup/github-app");
  return data;
}
