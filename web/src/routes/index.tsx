import { useEffect } from "react";
import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { AppShell } from "@/components/layout/AppShell";
import { FleetView } from "@/components/fleet/FleetView";
import { resolveCurrentUser, useAuth } from "@/lib/auth";

export const Route = createFileRoute("/")({
  beforeLoad: async ({ context, location }) => {
    if (!(await resolveCurrentUser(context.queryClient))) {
      throw redirect({
        to: "/login",
        search: location.href === "/" ? {} : { return_to: location.href },
        replace: true,
      });
    }
  },
  component: FleetPage,
});

function FleetPage() {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();
  const signedOut = !isLoading && !isAuthenticated;

  // The route guard ran before this rendered; this only handles the session
  // ending while the page is open. The effect depends on the auth state
  // alone, so it navigates once.
  useEffect(() => {
    if (signedOut) void navigate({ to: "/login", replace: true });
  }, [signedOut, navigate]);

  return <AppShell>{signedOut ? null : <FleetView />}</AppShell>;
}
