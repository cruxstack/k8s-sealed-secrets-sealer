import { createFileRoute } from "@tanstack/react-router";
import { FleetView } from "@/components/fleet/FleetView";
import { requireSignedIn, SignedInPage } from "@/lib/require-auth";

export const Route = createFileRoute("/fleet")({
  beforeLoad: requireSignedIn,
  component: FleetPage,
});

function FleetPage() {
  return (
    <SignedInPage>
      <FleetView />
    </SignedInPage>
  );
}
