import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/lib/auth";
import { EnvProvider } from "@/lib/env";
import { requireEnv, SignedInPage } from "@/lib/require-auth";

// Every page but signing in is about one env, named first in its path, so
// links to it keep their env.
export const Route = createFileRoute("/$env")({
  beforeLoad: requireEnv,
  component: EnvLayout,
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
      <Card className="mx-auto max-w-lg">
        <CardContent className="flex flex-col items-center gap-3 p-10 text-center">
          <ShieldAlert
            className="h-8 w-8 text-muted-foreground"
            aria-hidden="true"
          />
          <h1 className="font-semibold">
            You can't use the <span className="font-mono">{env}</span> env
          </h1>
          <p className="text-sm text-muted-foreground">
            It isn't one of this deployment's envs, or none of your teams may
            use it.
          </p>
          {envs.length > 0 && (
            <p className="flex flex-wrap justify-center gap-x-3 gap-y-1 text-sm">
              {envs.map((e) => (
                <Link
                  key={e.name}
                  to="/$env/secrets"
                  params={{ env: e.name }}
                  className="font-medium text-primary hover:underline"
                >
                  Go to {e.name}
                </Link>
              ))}
            </p>
          )}
        </CardContent>
      </Card>
    </SignedInPage>
  );
}
