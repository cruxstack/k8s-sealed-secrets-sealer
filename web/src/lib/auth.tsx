import { createContext, useContext, type ReactNode } from "react";
import { useQuery, type QueryClient } from "@tanstack/react-query";
import { authMeQueryOptions } from "@/api/queries/auth";
import type { AuthUser, EnvAccess, MeResponse } from "@/api/types";

interface AuthContextValue {
  user: AuthUser | null;
  /** The envs the user may use. */
  envs: EnvAccess[];
  isLoading: boolean;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  envs: [],
  isLoading: true,
  isAuthenticated: false,
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const { data, isLoading, isError } = useQuery(authMeQueryOptions);

  const value: AuthContextValue = {
    user: isError ? null : (data?.user ?? null),
    envs: isError ? [] : (data?.envs ?? []),
    isLoading,
    isAuthenticated: !isError && !!data?.user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}

/**
 * Resolve the signed-in session for route `beforeLoad` guards, or null when
 * there is none.
 *
 * Routes redirect from `beforeLoad` instead of rendering `<Navigate>`: a
 * `<Navigate>` re-navigates every time it re-renders with new props, and the
 * root re-renders on every router state change, so a render-time redirect
 * restarts its own navigation forever and freezes the page.
 *
 * A failed lookup is not retried here, so guards agree with what the
 * AuthProvider reports and `/` and `/login` cannot bounce between each
 * other. Signing in is a full-page OAuth round trip with a fresh cache.
 */
export async function resolveCurrentUser(
  queryClient: QueryClient,
): Promise<MeResponse | null> {
  const state = queryClient.getQueryState(authMeQueryOptions.queryKey);
  if (state?.status === "error") return null;
  try {
    return await queryClient.fetchQuery(authMeQueryOptions);
  } catch {
    return null;
  }
}
