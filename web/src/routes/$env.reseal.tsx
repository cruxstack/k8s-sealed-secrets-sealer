import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { ResealView } from "@/components/reseal/ResealView";
import { resealSearch } from "@/components/reseal/search";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { useEnv } from "@/lib/env";
import { SignedInPage } from "@/lib/require-auth";

export const Route = createFileRoute("/$env/reseal")({
  validateSearch: resealSearch,
  component: ResealPage,
});

/**
 * Resealing is for the env's admins; others are told so, not shown an
 * error.
 */
function ResealPage() {
  const env = useEnv();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <SignedInPage>
      {env?.admin ? (
        <ResealView
          search={search}
          onSearchChange={(patch) =>
            void navigate({
              search: (prev) => ({ ...prev, ...patch }),
              replace: true,
            })
          }
        />
      ) : (
        <EmptyState
          page
          icon={ShieldAlert}
          title="Resealing Is for Admins"
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/$env/secrets" params={{ env: env?.name ?? "" }}>
                Back to Secrets
              </Link>
            </Button>
          }
        >
          It moves the env's sealed values onto its env key, on a schedule or a
          file at a time. Ask an admin if values need resealing.
        </EmptyState>
      )}
    </SignedInPage>
  );
}
