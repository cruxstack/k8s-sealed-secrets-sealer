import { createContext, useContext, type ReactNode } from "react";
import type { QueryClient } from "@tanstack/react-query";
import { currentApiEnv, setApiEnv } from "@/api/client";
import type { EnvAccess } from "@/api/types";

/** The env a page is in, as the signed-in user may use it. */
const EnvContext = createContext<EnvAccess | null>(null);

export function EnvProvider({
  env,
  children,
}: {
  env: EnvAccess;
  children: ReactNode;
}) {
  return <EnvContext.Provider value={env}>{children}</EnvContext.Provider>;
}

/** The env the page is in; null outside an env (the login page). */
export function useEnv(): EnvAccess | null {
  return useContext(EnvContext);
}

/**
 * Point the API at an env. Moving to another env drops what was loaded for
 * the last one, since the cache is not keyed by env; signing-in data stays.
 */
export async function enterEnv(queryClient: QueryClient, env: string) {
  const previous = currentApiEnv();
  setApiEnv(env);
  if (previous === null || previous === env) return;
  const others = {
    predicate: (q: { queryKey: readonly unknown[] }) =>
      q.queryKey[0] !== "auth",
  };
  await queryClient.cancelQueries(others);
  queryClient.removeQueries(others);
}
