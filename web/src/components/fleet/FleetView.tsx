import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Server } from "lucide-react";
import { fleetQueryOptions } from "@/api/queries/fleet";
import { extractApiError } from "@/api/client";
import type { Fleet } from "@/api/types";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { AgentTable } from "./AgentTable";
import { EnvKeyBanner } from "./EnvKeyBanner";
import { KeyTable } from "./KeyTable";

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

/**
 * Warns when a cluster's keys reach half or 80% of the key limit, or go past
 * it, naming the cluster with the most.
 */
function KeyLimitNotice({ fleet }: { fleet: Fleet }) {
  const limit = fleet.key_limit;
  const agents = fleet.agents ?? [];
  if (!limit || agents.length === 0) return null;
  const most = agents.reduce((a, b) =>
    b.keys_reported > a.keys_reported ? b : a,
  );
  const n = most.keys_reported;
  if (n * 2 < limit) return null;
  const over = most.keys_dropped > 0;
  const others = agents.filter(
    (a) => a.id !== most.id && a.keys_reported * 2 >= limit,
  ).length;
  const name = most.cluster !== most.id ? most.cluster : most.id;
  const where = others > 0 ? `${name} (and ${others} more)` : name;
  return (
    <Card
      role={over ? "alert" : "status"}
      aria-label="Key limit"
      className={cn(over ? "border-destructive/50" : "border-warning/60")}
    >
      <CardContent className="flex items-start gap-3 p-4 text-sm">
        <AlertTriangle
          className={cn(
            "mt-0.5 h-4 w-4 shrink-0",
            over ? "text-destructive" : "text-warning",
          )}
          aria-hidden="true"
        />
        <div className="space-y-1">
          <p className="font-medium">
            {over
              ? `${where} reports ${n} keys, more than the ${limit} kept per cluster`
              : `${where} holds ${n} keys, ${Math.floor((n * 100) / limit)}% of the ${limit} kept per cluster`}
          </p>
          <p className="text-muted-foreground">
            {over
              ? `The ${most.keys_dropped} oldest are left out of key sync, so a cluster that joins does not get them.`
              : "Past the limit, the oldest keys are left out of key sync."}{" "}
            Keys only accumulate for now; keep key renewal on in one cluster to
            slow that.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

/** The fleet page: the env's key state, every registered agent and key. */
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
  const keys = data.keys ?? [];
  const revoked = keys.filter((k) => k.status === "revoked").length;

  return (
    <div className="space-y-6">
      <FleetHeader env={data.env} />

      <EnvKeyBanner fleet={data} />

      <KeyLimitNotice fleet={data} />

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
          <AgentTable
            agents={agents}
            envKey={data.env_key?.fingerprint}
            keyLimit={data.key_limit}
          />
        )}
      </section>

      {keys.length > 0 && (
        <section aria-labelledby="keys-heading" className="space-y-3">
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <div className="flex items-baseline gap-2">
              <h2 id="keys-heading" className="text-base font-semibold">
                Keys
              </h2>
              <span className="text-sm text-muted-foreground">
                {keys.length} {keys.length === 1 ? "key" : "keys"}
                {revoked > 0 && `, ${revoked} revoked`}
              </span>
            </div>
            <p className="text-xs text-muted-foreground">Newest first</p>
          </div>
          <KeyTable keys={keys} clusters={agents.length} />
        </section>
      )}
    </div>
  );
}
