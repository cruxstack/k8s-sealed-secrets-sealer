import type { FleetAgent } from "@/api/types";
import { Check, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { RegionTag } from "@/components/ui/region-tag";
import { RelativeTime } from "@/components/ui/relative-time";
import {
  Dash,
  Table,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { sentence, shortFingerprint, timeAgo } from "@/lib/utils";
import { countsReferences, plural } from "./references";

/** Health of one agent, as shown in the table. */
export function agentHealth(agent: FleetAgent): {
  label: string;
  variant: "success" | "destructive";
} {
  // an agent that never checked in cannot seal: a failure, not a warning
  if (!agent.checked_in)
    return { label: "Never checked in", variant: "destructive" };
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

/**
 * What an agent's latest count of key references found: the values in its
 * controller's SealedSecrets and when it counted, the namespaces when it
 * does not watch them all, and in the warning color the values none of the
 * cluster's keys decrypts. Agents without `cleanup` do not count.
 */
function KeyUsageCell({ agent, now }: { agent: FleetAgent; now: Date }) {
  const usage = agent.key_usage;
  if (!usage) {
    if (!agent.checked_in) return <Dash />;
    return countsReferences(agent) ? (
      <span className="text-xs whitespace-nowrap text-muted-foreground">
        Not counted yet
      </span>
    ) : (
      <span
        className="text-xs whitespace-nowrap text-muted-foreground"
        title="It counts key references only with the cleanup capability"
      >
        Doesn't count
      </span>
    );
  }
  const counted = (
    <RelativeTime
      iso={usage.counted_at}
      now={now}
      past
      describe={(at) => `Counted ${at}`}
    />
  );
  if (usage.error) {
    return (
      <div className="max-w-32 space-y-0.5 text-xs">
        <p className="font-medium text-destructive">Count failed {counted}</p>
        {/* an error names API groups and resources, long unbroken words */}
        <p className="text-muted-foreground [overflow-wrap:anywhere]">
          {sentence(usage.error)}
        </p>
      </div>
    );
  }
  const namespaces = usage.namespaces ?? [];
  return (
    // one count per line, wrapping past 8rem, so the column stays narrow
    // beside the issues and never spills into them
    <div className="max-w-32 space-y-0.5">
      <p className="whitespace-nowrap tabular-nums">
        {plural(usage.values, "value")}
      </p>
      <p className="text-xs whitespace-nowrap text-muted-foreground tabular-nums">
        in {plural(usage.sealed_secrets, "SealedSecret")}
      </p>
      {usage.unmatched > 0 && (
        <p
          className="flex items-center gap-1 text-xs font-semibold whitespace-nowrap text-warning"
          title="Values none of this cluster's keys decrypts: the controller cannot decrypt them either"
        >
          <TriangleAlert className="h-3 w-3 shrink-0" aria-hidden="true" />
          {usage.unmatched} unmatched
        </p>
      )}
      <p className="text-xs whitespace-nowrap text-muted-foreground">
        counted {counted}
      </p>
      {namespaces.length > 0 && (
        // namespace names are long and unbroken: listed in full they ran
        // down the narrow column a fragment a line, so only their count
        // shows, with the names in the title and for a screen reader
        <p
          className="text-xs whitespace-nowrap text-muted-foreground"
          title={namespaces.join("\n")}
        >
          in {plural(namespaces.length, "namespace")}
          <span className="sr-only">: {namespaces.join(", ")}</span>
        </p>
      )}
    </div>
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
  const capabilities = [
    ...(agent.capabilities ?? agent.registered_capabilities ?? []),
  ].sort();
  const active = agent.controller?.active_fingerprint;
  // the cluster, when its name says more than the agent's
  const cluster = agent.cluster !== agent.id ? agent.cluster : "";

  return (
    <TableRow className="align-top">
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
      <TableCell className="whitespace-nowrap">
        {agent.region ? <RegionTag region={agent.region} /> : <Dash />}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        {/* the time under the badge, as a key's status shows it, so the
            table fits a laptop with the sealed values column */}
        <span className="flex flex-col items-start gap-0.5">
          <Badge variant={health.variant}>{health.label}</Badge>
          {agent.last_checkin && (
            <RelativeTime
              className="text-xs text-muted-foreground"
              iso={agent.last_checkin}
              now={now}
              past
              describe={(at) => `Last check-in ${at}`}
            />
          )}
        </span>
      </TableCell>
      <TableCell className="pt-3.5 font-mono text-xs">
        {agent.agent_version ?? <Dash />}
      </TableCell>
      <TableCell>
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
      </TableCell>
      <TableCell className="text-right tabular-nums">
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
      </TableCell>
      <TableCell className="text-right whitespace-nowrap tabular-nums">
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
      </TableCell>
      <TableCell>
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
      </TableCell>
      <TableCell>
        <KeyUsageCell agent={agent} now={now} />
      </TableCell>
      {/* issues are sentences: never squeezed to a word a line */}
      <TableCell className="min-w-40 text-xs">
        {issues.length > 0 ? (
          <ul className="list-disc space-y-1 pl-4">
            {issues.map((issue) => (
              <li key={issue}>{issue}</li>
            ))}
          </ul>
        ) : (
          <Dash />
        )}
      </TableCell>
    </TableRow>
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
    <Table>
      <caption className="sr-only">Agents in this env</caption>
      <TableHeader>
        <tr>
          <TableHead>Agent</TableHead>
          <TableHead>Region</TableHead>
          <TableHead>Health</TableHead>
          <TableHead>Version</TableHead>
          <TableHead>Capabilities</TableHead>
          <TableHead className="text-right">Keys</TableHead>
          <TableHead className="text-right">Missing</TableHead>
          <TableHead>Active key</TableHead>
          <TableHead>Sealed values</TableHead>
          <TableHead>Issues</TableHead>
        </tr>
      </TableHeader>
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
    </Table>
  );
}
