import { useQuery } from "@tanstack/react-query";
import { Server } from "lucide-react";
import { fleetQueryOptions } from "@/api/queries/fleet";
import { extractApiError } from "@/api/client";
import type { Fleet } from "@/api/types";
import { Alert } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { SectionHeading } from "@/components/ui/section-heading";
import { Skeleton } from "@/components/ui/skeleton";
import { sentence } from "@/lib/utils";
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
    <Alert
      variant={over ? "destructive" : "warning"}
      role={over ? "alert" : "status"}
      aria-label="Key limit"
      heading={
        over
          ? `${where} reports ${n} keys, more than the ${limit} kept per cluster`
          : `${where} holds ${n} keys, ${Math.floor((n * 100) / limit)}% of the ${limit} kept per cluster`
      }
    >
      {over
        ? `The ${most.keys_dropped} oldest are left out of key sync, so a cluster that joins does not get them.`
        : "Past the limit, the oldest keys are left out of key sync."}{" "}
      Keys only accumulate for now; keep key renewal on in one cluster to slow
      that.
    </Alert>
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
        <Alert
          variant="destructive"
          role="alert"
          heading="Could not load the fleet"
        >
          {sentence(extractApiError(error))}
        </Alert>
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
        <SectionHeading
          id="agents-heading"
          title="Agents"
          count={
            agents.length > 0
              ? `${healthy} of ${agents.length} healthy`
              : undefined
          }
          // a count that needs attention is amber
          countClassName={
            healthy === agents.length ? undefined : "text-warning"
          }
          aside="Refreshes every 15 seconds"
        />

        {agents.length === 0 ? (
          <EmptyState icon={Server} title="No agents registered">
            Nothing can be sealed until an agent checks in. Add agents to the
            control plane's agent registry; each one appears here once it is
            registered.
          </EmptyState>
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
          <SectionHeading
            id="keys-heading"
            title="Keys"
            count={`${keys.length} ${keys.length === 1 ? "key" : "keys"}${revoked > 0 ? `, ${revoked} revoked` : ""}`}
            aside="Newest first"
          />
          <KeyTable keys={keys} clusters={agents.length} />
        </section>
      )}
    </div>
  );
}
