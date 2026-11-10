import { useQuery } from "@tanstack/react-query";
import { Server } from "lucide-react";
import { fleetQueryOptions } from "@/api/queries/fleet";
import { extractApiError } from "@/api/client";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { AgentTable } from "./AgentTable";
import { EnvKeyBanner } from "./EnvKeyBanner";

function FleetHeader({ env }: { env?: string }) {
  return (
    <header className="space-y-1">
      <h1 className="text-xl font-semibold tracking-tight">Fleet</h1>
      <p className="text-sm text-muted-foreground">
        {env ? (
          <>
            The agents of the{" "}
            <span className="font-medium text-foreground">{env}</span> env and
            the keys their clusters hold.
          </>
        ) : (
          "The env's agents and the keys their clusters hold."
        )}{" "}
        Only admins see this page.
      </p>
    </header>
  );
}

/** The fleet page: the env's key state and every registered agent. */
export function FleetView() {
  const { data, error, isPending } = useQuery(fleetQueryOptions);

  if (isPending) {
    return (
      <div className="space-y-6">
        <FleetHeader />
        <div className="space-y-6" aria-busy="true" aria-label="Loading fleet">
          <Skeleton className="h-28 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="space-y-6">
        <FleetHeader />
        <Card role="alert" className="border-destructive/50">
          <CardContent className="p-6 text-sm text-destructive">
            Could not load the fleet: {extractApiError(error)}
          </CardContent>
        </Card>
      </div>
    );
  }

  const agents = data.agents ?? [];
  const healthy = agents.filter((a) => a.checked_in && a.healthy).length;

  return (
    <div className="space-y-6">
      <FleetHeader env={data.env} />

      <EnvKeyBanner fleet={data} />

      <section aria-labelledby="agents-heading" className="space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <div className="flex items-baseline gap-2">
            <h2 id="agents-heading" className="text-base font-semibold">
              Agents
            </h2>
            {agents.length > 0 && (
              <span
                className={
                  healthy === agents.length
                    ? "text-sm text-muted-foreground"
                    : "text-sm text-warning"
                }
              >
                {healthy} of {agents.length} healthy
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Refreshes every 15 seconds
          </p>
        </div>

        {agents.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
              <Server
                className="h-8 w-8 text-muted-foreground"
                aria-hidden="true"
              />
              <p className="font-medium">No agents registered</p>
              <p className="max-w-sm text-sm text-muted-foreground">
                Add agents to the control plane's agent registry. Each one
                appears here once it is registered.
              </p>
            </CardContent>
          </Card>
        ) : (
          <AgentTable agents={agents} envKey={data.env_key?.fingerprint} />
        )}
      </section>
    </div>
  );
}
