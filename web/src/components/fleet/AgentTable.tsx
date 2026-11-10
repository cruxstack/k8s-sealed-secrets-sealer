import type { FleetAgent } from "@/api/types";
import { Check } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { formatDateTime, shortFingerprint, timeAgo } from "@/lib/utils";

/** Health of one agent, as shown in the table. */
export function agentHealth(agent: FleetAgent): {
  label: string;
  variant: "success" | "destructive" | "secondary";
} {
  if (!agent.checked_in)
    return { label: "Never checked in", variant: "secondary" };
  if (!agent.healthy) return { label: "Unhealthy", variant: "destructive" };
  return { label: "Healthy", variant: "success" };
}

/**
 * How many keys an agent reports, in the warning color from half the key
 * limit, with how many were left out past it.
 */
function KeyCount({
  agent,
  keyLimit,
}: {
  agent: FleetAgent;
  keyLimit?: number;
}) {
  const n = agent.keys_reported || (agent.keys ?? []).length;
  if (!keyLimit || n * 2 < keyLimit) return <>{n}</>;
  const dropped = agent.keys_dropped;
  return (
    <span
      className="font-semibold text-warning"
      title={
        dropped > 0
          ? `More than the ${keyLimit} kept per cluster: the ${dropped} oldest are left out of key sync`
          : `${Math.floor((n * 100) / keyLimit)}% of the ${keyLimit} kept per cluster`
      }
    >
      {n}
      {dropped > 0 && (
        <span className="ml-1 text-xs font-normal">({dropped} left out)</span>
      )}
    </span>
  );
}

function Dash() {
  return (
    <span className="text-muted-foreground" aria-label="none">
      —
    </span>
  );
}

function AgentRow({
  agent,
  envKey,
  keyLimit,
  now,
}: {
  agent: FleetAgent;
  envKey?: string;
  keyLimit?: number;
  now: Date;
}) {
  const health = agentHealth(agent);
  const missing = agent.missing_keys ?? [];
  const issues = agent.issues ?? [];
  const capabilities =
    agent.capabilities ?? agent.registered_capabilities ?? [];
  const active = agent.controller?.active_fingerprint;
  // the cluster, when its name says more than the agent's
  const cluster = agent.cluster !== agent.id ? agent.cluster : "";

  return (
    <tr className="border-b border-border align-top last:border-0">
      <th
        scope="row"
        className="px-4 py-3 text-left font-mono text-sm font-medium whitespace-nowrap"
      >
        {agent.id}
        {cluster && (
          <>
            {" "}
            <span className="block font-sans text-xs font-normal text-muted-foreground">
              {cluster}
            </span>
          </>
        )}
      </th>
      <td className="px-4 py-3 whitespace-nowrap">{agent.region}</td>
      <td className="px-4 py-3 whitespace-nowrap">
        <Badge variant={health.variant}>{health.label}</Badge>
        {agent.last_checkin && (
          <time
            className="ml-2 text-xs text-muted-foreground"
            dateTime={agent.last_checkin}
            title={`Last check-in ${formatDateTime(agent.last_checkin)}`}
          >
            {timeAgo(agent.last_checkin, now)}
          </time>
        )}
      </td>
      <td className="px-4 py-3 pt-3.5 font-mono text-xs">
        {agent.agent_version ?? <Dash />}
      </td>
      <td className="px-4 py-3">
        {capabilities.length > 0 ? (
          <ul className="flex gap-1" aria-label="Capabilities">
            {capabilities.map((c) => (
              <li key={c}>
                <Badge variant="outline">{c}</Badge>
              </li>
            ))}
          </ul>
        ) : (
          <Dash />
        )}
      </td>
      <td className="px-4 py-3 text-right tabular-nums">
        {agent.checked_in ? (
          <>
            <KeyCount agent={agent} keyLimit={keyLimit} />
            {!agent.keys_complete && (
              <span className="ml-1 text-xs text-muted-foreground">
                (active only)
              </span>
            )}
          </>
        ) : (
          <Dash />
        )}
      </td>
      <td className="px-4 py-3 text-right whitespace-nowrap tabular-nums">
        {agent.joining && (
          <Badge
            variant="warning"
            className="mr-2"
            title={
              agent.joined_at
                ? `Joined ${timeAgo(agent.joined_at, now)}; left out of the env key for up to 30 minutes while it restores the env's keys`
                : undefined
            }
          >
            Joining
          </Badge>
        )}
        {agent.in_scope ? (
          missing.length > 0 ? (
            <span
              className="font-semibold text-warning"
              title={missing.join("\n")}
            >
              {missing.length}
            </span>
          ) : (
            "0"
          )
        ) : (
          <Dash />
        )}
      </td>
      <td className="px-4 py-3">
        {active ? (
          <span className="flex items-center gap-1.5 whitespace-nowrap">
            <code className="font-mono text-xs" title={active}>
              {shortFingerprint(active)}
            </code>
            {active === envKey && (
              <span title="The env key: values are sealed with it">
                <Check
                  className="h-3.5 w-3.5 text-success"
                  aria-hidden="true"
                />
                <span className="sr-only">env key</span>
              </span>
            )}
          </span>
        ) : (
          <Dash />
        )}
      </td>
      <td className="px-4 py-3 text-xs">
        {issues.length > 0 ? (
          <ul className="list-disc space-y-1 pl-4">
            {issues.map((issue) => (
              <li key={issue}>{issue}</li>
            ))}
          </ul>
        ) : (
          <Dash />
        )}
      </td>
    </tr>
  );
}

/** One row per registered agent. */
export function AgentTable({
  agents,
  envKey,
  keyLimit,
  now = new Date(),
}: {
  agents: FleetAgent[];
  /** The env key's fingerprint, to mark the agents whose active key it is. */
  envKey?: string;
  /** How many keys of a cluster are kept, to warn as a cluster nears it. */
  keyLimit?: number;
  now?: Date;
}) {
  return (
    <div className="overflow-x-auto rounded-xl border bg-card">
      <table className="w-full text-sm">
        <caption className="sr-only">Agents in this environment</caption>
        <thead className="border-b border-border bg-muted/50 text-xs tracking-wide whitespace-nowrap text-muted-foreground uppercase">
          <tr>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Agent
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Region
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Health
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Version
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Capabilities
            </th>
            <th scope="col" className="px-4 py-3 text-right font-semibold">
              Keys
            </th>
            <th scope="col" className="px-4 py-3 text-right font-semibold">
              Missing
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Active key
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Issues
            </th>
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <AgentRow
              key={agent.id}
              agent={agent}
              envKey={envKey}
              keyLimit={keyLimit}
              now={now}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}
