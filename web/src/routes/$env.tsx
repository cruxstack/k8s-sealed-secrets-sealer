import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { NotFound } from "@/components/layout/NotFound";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { useAuth } from "@/lib/auth";
import { EnvProvider } from "@/lib/env";
import { requireEnv, SignedInPage } from "@/lib/require-auth";

// Every page but signing in is about one env, named first in its path, so
// links to it keep their env.
export const Route = createFileRoute("/$env")({
  beforeLoad: requireEnv,
  component: EnvLayout,
  notFoundComponent: NotFound,
});

function EnvLayout() {
  const { envAccess } = Route.useRouteContext();
  const { env } = Route.useParams();
  if (!envAccess) return <NoAccess env={env} />;
  // a new env starts its pages afresh, so nothing loaded for another shows
  return (
    <EnvProvider key={envAccess.name} env={envAccess}>
      <Outlet />
    </EnvProvider>
  );
}

/** An env the user may not use, or that does not exist. */
function NoAccess({ env }: { env: string }) {
  const { envs } = useAuth();
  return (
    <SignedInPage>
      <EmptyState
        page
        icon={ShieldAlert}
        title={`You can't use the ${env} env`}
        action={
          envs.length > 0
            ? envs.map((e) => (
                <Button key={e.name} asChild variant="outline" size="sm">
                  <Link to="/$env/secrets" params={{ env: e.name }}>
                    Go to {e.name}
                  </Link>
                </Button>
              ))
            : undefined
        }
      >
        It isn't one of this deployment's envs, or none of your teams may use
        it.
      </EmptyState>
    </SignedInPage>
  );
}
