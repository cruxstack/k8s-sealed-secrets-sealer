import type { FleetAgent } from "@/api/types";
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

function Dash() {
  return (
    <span className="text-muted-foreground" aria-label="none">
      —
    </span>
  );
}

function AgentRow({ agent, now }: { agent: FleetAgent; now: Date }) {
  const health = agentHealth(agent);
  const keys = agent.keys ?? [];
  const missing = agent.missing_keys ?? [];
  const issues = agent.issues ?? [];
  const capabilities =
    agent.capabilities ?? agent.registered_capabilities ?? [];
  const active = agent.controller?.active_fingerprint;

  return (
    <tr className="border-b border-border last:border-0 align-top">
      <th
        scope="row"
        className="px-4 py-3 text-left font-mono text-sm font-medium whitespace-nowrap"
      >
        {agent.id}
      </th>
      <td className="px-4 py-3 whitespace-nowrap">{agent.region}</td>
      <td className="px-4 py-3 whitespace-nowrap">{agent.cluster}</td>
      <td className="px-4 py-3">
        <Badge variant={health.variant}>{health.label}</Badge>
      </td>
      <td className="px-4 py-3 whitespace-nowrap">
        {agent.last_checkin ? (
          <time
            dateTime={agent.last_checkin}
            title={formatDateTime(agent.last_checkin)}
          >
            {timeAgo(agent.last_checkin, now)}
          </time>
        ) : (
          <Dash />
        )}
      </td>
      <td className="px-4 py-3 font-mono text-xs">
        {agent.agent_version ?? <Dash />}
      </td>
      <td className="px-4 py-3">
        {capabilities.length > 0 ? (
          <ul className="flex flex-wrap gap-1" aria-label="Capabilities">
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
            {keys.length}
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
      <td className="px-4 py-3 text-right tabular-nums">
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
          <code className="font-mono text-xs" title={active}>
            {shortFingerprint(active)}
          </code>
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
  now = new Date(),
}: {
  agents: FleetAgent[];
  now?: Date;
}) {
  return (
    <div className="overflow-x-auto rounded-xl border bg-card">
      <table className="w-full text-sm">
        <caption className="sr-only">Agents in this environment</caption>
        <thead className="border-b border-border bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
          <tr>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Agent
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Region
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Cluster
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Health
            </th>
            <th scope="col" className="px-4 py-3 text-left font-semibold">
              Last check-in
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
            <AgentRow key={agent.id} agent={agent} now={now} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
