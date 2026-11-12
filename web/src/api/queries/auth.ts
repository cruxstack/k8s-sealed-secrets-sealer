import {
  queryOptions,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import apiClient, { navigation, setCsrfToken } from "@/api/client";
import type { MeResponse } from "@/api/types";
import { forgetBrowserData } from "@/lib/repo-cache";

export const authMeQueryOptions = queryOptions({
  queryKey: ["auth", "me"],
  queryFn: async () => {
    const { data } = await apiClient.get<MeResponse>("/auth/me");
    setCsrfToken(data.csrf_token);
    return data;
  },
  retry: false,
  // The route guards already fetched this; a 401 means signed out, so don't
  // refetch it when the AuthProvider mounts (see resolveCurrentUser).
  retryOnMount: false,
  staleTime: 5 * 60_000,
});

export function useLogout() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      // before the request: someone signing out of a shared browser wants
      // nothing of theirs left in it, even if the server can't be reached
      forgetBrowserData();
      await apiClient.post("/auth/logout");
    },
    onSuccess: () => {
      setCsrfToken(null);
      queryClient.clear();
      navigation.assign("/login");
    },
  });
}
