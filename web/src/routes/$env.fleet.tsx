import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { FleetView } from "@/components/fleet/FleetView";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { useEnv } from "@/lib/env";
import { SignedInPage } from "@/lib/require-auth";

export const Route = createFileRoute("/$env/fleet")({
  component: FleetPage,
});

/**
 * The fleet is for the env's admins; others are told so, not shown an
 * error.
 */
function FleetPage() {
  const env = useEnv();
  return (
    <SignedInPage>
      {env?.admin ? (
        <FleetView />
      ) : (
        <EmptyState
          page
          icon={ShieldAlert}
          title="The Fleet Is for Admins"
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/$env/secrets" params={{ env: env?.name ?? "" }}>
                Back to Secrets
              </Link>
            </Button>
          }
        >
          It shows every cluster's agent and keys. The env badge at the top says
          whether sealing works; ask an admin about anything more.
        </EmptyState>
      )}
    </SignedInPage>
  );
}
