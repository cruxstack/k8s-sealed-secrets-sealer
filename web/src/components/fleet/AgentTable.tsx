import { useId, useState } from "react";
import { Check, ChevronRight, TriangleAlert } from "lucide-react";
import type { FleetAgent } from "@/api/types";
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
import { cn, sentence, shortFingerprint, timeAgo } from "@/lib/utils";
import { countsReferences, plural } from "./references";

/** Health of one agent, as shown in the table. */
export function agentHealth(agent: FleetAgent): {
  label: string;
  variant: "success" | "destructive";
} {
  // an agent that never checked in cannot seal: a failure, not a warning
  if (!agent.checked_in)
    return { label: "Never Checked In", variant: "destructive" };
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
 * What an agent's latest count of key references found, on one line: the
 * values in its controller's SealedSecrets, and in the warning color the
 * values none of the cluster's keys decrypts. When and where it counted
 * are in the agent's details. Agents without `cleanup` do not count.
 */
function KeyUsageCell({ agent, now }: { agent: FleetAgent; now: Date }) {
  const usage = agent.key_usage;
  if (!usage) {
    if (!agent.checked_in) return <Dash />;
    return countsReferences(agent) ? (
      <span className="text-xs text-muted-foreground">Not counted yet</span>
    ) : (
      <span
        className="text-xs text-muted-foreground"
        title="It counts key references only with the cleanup capability"
      >
        Doesn't count
      </span>
    );
  }
  if (usage.error) {
    return (
      <span className="text-xs font-medium text-destructive">
        Count failed{" "}
        <RelativeTime
          iso={usage.counted_at}
          now={now}
          past
          describe={(at) => `Counted ${at}`}
        />
      </span>
    );
  }
  return (
    <span className="inline-flex items-baseline gap-2">
      <span
        className="tabular-nums"
        title={`Counted ${timeAgo(usage.counted_at, now)}`}
      >
        {plural(usage.values, "value")}{" "}
        <span className="text-xs text-muted-foreground">
          in {plural(usage.sealed_secrets, "SealedSecret")}
        </span>
      </span>
      {usage.unmatched > 0 && (
        <span
          className="inline-flex items-center gap-1 self-center text-xs font-semibold text-warning"
          title="Values none of this cluster's keys decrypts: the controller cannot decrypt them either"
        >
          <TriangleAlert className="h-3 w-3 shrink-0" aria-hidden="true" />
          {usage.unmatched} unmatched
        </span>
      )}
    </span>
  );
}

/** When and where an agent last counted, for its details. */
function CountDetail({ agent, now }: { agent: FleetAgent; now: Date }) {
  const usage = agent.key_usage;
  if (!usage) {
    if (!agent.checked_in) return <Dash />;
    return countsReferences(agent) ? (
      <>Not counted yet.</>
    ) : (
      <>It counts key references only with the cleanup capability.</>
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
      // an error names API groups and resources, long unbroken words
      <span className="[overflow-wrap:anywhere]">
        <span className="font-medium text-destructive">Failed {counted}:</span>{" "}
        {sentence(usage.error)}
      </span>
    );
  }
  const namespaces = usage.namespaces ?? [];
  return (
    <span className="[overflow-wrap:anywhere]">
      Counted {counted}
      {namespaces.length > 0 ? (
        <>
          , in {plural(namespaces.length, "namespace")}:{" "}
          <span className="font-mono">{namespaces.join(", ")}</span>
        </>
      ) : (
        ", in every namespace"
      )}
    </span>
  );
}

/**
 * Issues the health badge already says, left out of an agent's issues so
 * they are not said twice.
 */
const SAID_BY_HEALTH = new Set([
  "has never checked in",
  "has not checked in recently",
]);

/** The agent table's columns, for the row of details under an agent. */
const COLUMNS = 6;

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
  const [open, setOpen] = useState(false);
  const detailId = useId();
  const health = agentHealth(agent);
  const missing = agent.missing_keys ?? [];
  const issues = (agent.issues ?? []).filter((i) => !SAID_BY_HEALTH.has(i));
  const capabilities = [
    ...(agent.capabilities ?? agent.registered_capabilities ?? []),
  ].sort();
  const active = agent.controller?.active_fingerprint;
  // the cluster, when its name says more than the agent's
  const cluster = agent.cluster !== agent.id ? agent.cluster : "";
  const toggle = () => setOpen((o) => !o);

  return (
    <>
      {/* one line a row: what does not fit is in the agent's details */}
      <TableRow
        className={cn(
          "[&>td]:whitespace-nowrap [&>th]:whitespace-nowrap",
          // the details under it belong to this row
          open && "border-b-0",
        )}
      >
        <th scope="row" className="px-4 py-3 text-left font-normal">
          <span className="inline-flex items-center gap-2">
            <button
              type="button"
              onClick={toggle}
              aria-expanded={open}
              aria-controls={open ? detailId : undefined}
              title={open ? "Hide Details" : "Show Details"}
              className="group inline-flex items-center gap-1 rounded-sm font-mono text-sm font-medium hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              <ChevronRight
                className={cn(
                  "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
                  open && "rotate-90",
                )}
                aria-hidden="true"
              />
              {agent.id}
            </button>{" "}
            {agent.region && <RegionTag region={agent.region} />}
          </span>
        </th>
        <TableCell>
          <span className="inline-flex items-center gap-2">
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
            {issues.length > 0 && (
              <button
                type="button"
                onClick={toggle}
                aria-expanded={open}
                aria-controls={open ? detailId : undefined}
                className="inline-flex items-center gap-1 rounded-sm text-xs font-semibold text-warning hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                <TriangleAlert
                  className="h-3 w-3 shrink-0"
                  aria-hidden="true"
                />
                {plural(issues.length, "Issue")}
              </button>
            )}
          </span>
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
        <TableCell className="text-right tabular-nums">
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
            <span className="inline-flex items-center gap-1.5">
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
      </TableRow>
      {open && (
        <TableRow id={detailId} className="bg-muted/30">
          <td colSpan={COLUMNS} className="px-4 pt-1 pb-3">
            {/* sticky: the table may be scrolled sideways on a phone */}
            <dl
              aria-label={`Details of ${agent.id}`}
              className="sticky left-4 grid w-fit max-w-[calc(100vw-4rem)] grid-cols-[auto_minmax(0,1fr)] gap-x-6 gap-y-2 text-xs sm:max-w-3xl"
            >
              {cluster && (
                <>
                  <dt className="text-muted-foreground">Cluster</dt>
                  <dd className="font-mono">{cluster}</dd>
                </>
              )}
              <dt className="text-muted-foreground">Version</dt>
              <dd className="font-mono">{agent.agent_version ?? <Dash />}</dd>
              <dt className="text-muted-foreground">Capabilities</dt>
              <dd>
                {capabilities.length > 0 ? (
                  <ul
                    className="flex flex-wrap gap-1"
                    aria-label="Capabilities"
                  >
                    {capabilities.map((c) => (
                      <li key={c}>
                        <Badge variant="outline">{c}</Badge>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Dash />
                )}
              </dd>
              <dt className="text-muted-foreground">Sealed Values</dt>
              <dd>
                <CountDetail agent={agent} now={now} />
              </dd>
              {issues.length > 0 && (
                <>
                  <dt className="text-muted-foreground">Issues</dt>
                  <dd>
                    <ul
                      className="list-disc space-y-0.5 pl-4 marker:text-warning"
                      aria-label={`Issues of ${agent.id}`}
                    >
                      {issues.map((issue) => (
                        <li key={issue}>{sentence(issue)}</li>
                      ))}
                    </ul>
                  </dd>
                </>
              )}
            </dl>
          </td>
        </TableRow>
      )}
    </>
  );
}

/**
 * One row per registered agent, on one line, with its details (cluster,
 * version, capabilities, its count and its issues) in a row under it that
 * the agent's name opens.
 */
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
          <TableHead>Health</TableHead>
          <TableHead className="text-right">Keys</TableHead>
          <TableHead className="text-right">Missing</TableHead>
          <TableHead>Active Key</TableHead>
          <TableHead>Sealed Values</TableHead>
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
