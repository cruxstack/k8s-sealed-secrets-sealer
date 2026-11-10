import { useQuery } from "@tanstack/react-query";
import { Server } from "lucide-react";
import { fleetQueryOptions } from "@/api/queries/fleet";
import { extractApiError } from "@/api/client";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { AgentTable } from "./AgentTable";
import { EnvKeyBanner } from "./EnvKeyBanner";

/** The fleet page: the env's key state and every registered agent. */
export function FleetView() {
  const { data, error, isPending } = useQuery(fleetQueryOptions);

  if (isPending) {
    return (
      <div className="space-y-6" aria-busy="true" aria-label="Loading fleet">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error && !data) {
    return (
      <Card role="alert" className="border-destructive/50">
        <CardContent className="p-6 text-sm text-destructive">
          Could not load the fleet: {extractApiError(error)}
        </CardContent>
      </Card>
    );
  }

  const agents = data.agents ?? [];

  return (
    <div className="space-y-6">
      <EnvKeyBanner fleet={data} />

      <section aria-labelledby="agents-heading" className="space-y-3">
        <div className="flex items-baseline justify-between">
          <h2 id="agents-heading" className="text-lg font-semibold">
            Agents
          </h2>
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
          <AgentTable agents={agents} />
        )}
      </section>
    </div>
  );
}
