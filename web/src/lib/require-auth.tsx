import { useEffect, type ReactNode } from "react";
import { redirect, useNavigate } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import { AppShell } from "@/components/layout/AppShell";
import { resolveCurrentUser, useAuth } from "@/lib/auth";

/**
 * A `beforeLoad` guard for signed-in pages: without a session it redirects
 * to the login page, which brings the user back afterwards.
 */
export async function requireSignedIn({
  context,
  location,
}: {
  context: { queryClient: QueryClient };
  location: { href: string };
}) {
  if (!(await resolveCurrentUser(context.queryClient))) {
    throw redirect({
      to: "/login",
      search: location.href === "/" ? {} : { return_to: location.href },
      replace: true,
    });
  }
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
