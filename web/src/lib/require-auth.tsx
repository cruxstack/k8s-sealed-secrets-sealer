import { useEffect, type ReactNode } from "react";
import { redirect, useNavigate } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import type { EnvAccess, MeResponse } from "@/api/types";
import { AppShell } from "@/components/layout/AppShell";
import { resolveCurrentUser, useAuth } from "@/lib/auth";
import { enterEnv } from "@/lib/env";

interface GuardOptions {
  context: { queryClient: QueryClient };
  location: { href: string };
}

/**
 * A `beforeLoad` guard for signed-in pages: without a session it redirects
 * to the login page, which brings the user back afterwards.
 */
export async function requireSignedIn({
  context,
  location,
}: GuardOptions): Promise<MeResponse> {
  const me = await resolveCurrentUser(context.queryClient);
  if (!me) {
    throw redirect({
      to: "/login",
      search: location.href === "/" ? {} : { return_to: location.href },
      replace: true,
    });
  }
  return me;
}

/**
 * The guard of an env's pages: signed in, and pointing the API at the env
 * when the user may use it. The env is null when they may not.
 */
export async function requireEnv(
  opts: GuardOptions & { params: { env: string } },
): Promise<{ envAccess: EnvAccess | null }> {
  const me = await requireSignedIn(opts);
  const envAccess = me.envs.find((e) => e.name === opts.params.env) ?? null;
  if (envAccess) await enterEnv(opts.context.queryClient, envAccess.name);
  return { envAccess };
}

/** The env a signed-in user starts in: the first they may use. */
export async function homeEnv(opts: GuardOptions): Promise<string> {
  const me = await requireSignedIn(opts);
  const first = me.envs[0];
  if (!first) {
    // a session always grants an env; sign in again if this one doesn't
    throw redirect({ to: "/login", replace: true });
  }
  return first.name;
}

/**
 * The shell of a signed-in page. The route guard ran before this rendered;
 * this only handles the session ending while the page is open. The effect
 * depends on the auth state alone, so it navigates once.
 */
export function SignedInPage({ children }: { children: ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();
  const signedOut = !isLoading && !isAuthenticated;

  useEffect(() => {
    if (signedOut) void navigate({ to: "/login", replace: true });
  }, [signedOut, navigate]);

  return <AppShell>{signedOut ? null : children}</AppShell>;
}
