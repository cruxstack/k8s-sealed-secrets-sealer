import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { FleetView } from "@/components/fleet/FleetView";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/lib/auth";
import { requireSignedIn, SignedInPage } from "@/lib/require-auth";

export const Route = createFileRoute("/fleet")({
  beforeLoad: requireSignedIn,
  component: FleetPage,
});

/** The fleet is for admins; others are told so, not shown an error. */
function FleetPage() {
  const { user } = useAuth();
  return (
    <SignedInPage>
      {user?.admin ? (
        <FleetView />
      ) : (
        <Card className="mx-auto max-w-lg">
          <CardContent className="flex flex-col items-center gap-3 p-10 text-center">
            <ShieldAlert
              className="h-8 w-8 text-muted-foreground"
              aria-hidden="true"
            />
            <h1 className="font-semibold">The fleet is for admins</h1>
            <p className="text-sm text-muted-foreground">
              It shows every cluster's agent and keys. The env badge at the top
              says whether sealing works; ask an admin about anything more.
            </p>
            <Link
              to="/secrets"
              className="text-sm font-medium text-primary hover:underline"
            >
              Back to your secrets
            </Link>
          </CardContent>
        </Card>
      )}
    </SignedInPage>
  );
}
