import { Fragment } from "react";
import { ChevronDown } from "lucide-react";
import type { FleetAgent, FleetKey } from "@/api/types";
import { RelativeTime } from "@/components/ui/relative-time";
import {
  Dash,
  Table,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn, shortFingerprint } from "@/lib/utils";
import { plural, referenceSummary, uncountedReason } from "./references";

/** Agent IDs in monospace, as in a sentence: "a, b". */
function AgentList({ ids }: { ids: string[] }) {
  return ids.map((id, i) => (
    <Fragment key={id}>
      {i > 0 && ", "}
      <code className="font-mono">{id}</code>
    </Fragment>
  ));
}

/** The clusters that did not count, named when there are one or two. */
function NotCounted({ ids }: { ids: string[] }) {
  return (
    <>
      not counted in{" "}
      {ids.length <= 2 ? (
        <AgentList ids={ids} />
      ) : (
        plural(ids.length, "cluster")
      )}
    </>
  );
}

/** NotCounted's words, for the button's name. */
function notCountedText(ids: string[]): string {
  return `not counted in ${ids.length <= 2 ? ids.join(", ") : plural(ids.length, "cluster")}`;
}

/**
 * A key's references in its row: "None", "12 values in 4 SealedSecrets",
 * or, when a cluster did not count, "Unknown" or "At least 12 values" with
 * the clusters left out. It is the button that shows the count per cluster
 * in a row under it, so the breakdown works with a keyboard and on a touch
 * screen. `counting` is false when no agent counts at all; the fleet says
 * why above the table, and the cell is a dash.
 */
export function ReferencesCell({
  fleetKey,
  counting,
  expanded,
  detailId,
  onToggle,
}: {
  fleetKey: FleetKey;
  counting: boolean;
  expanded: boolean;
  detailId: string;
  onToggle: () => void;
}) {
  const summary = referenceSummary(fleetKey.references);
  if (
    !counting ||
    (summary.kind === "unknown" && summary.uncounted.length === 0)
  ) {
    return <Dash label="not counted" />;
  }
  let primary: string;
  let detail = null;
  // the second line's words, so the two lines read as one name
  let detailText = "";
  switch (summary.kind) {
    case "none":
      primary = "None";
      break;
    case "known":
      primary = plural(summary.values, "value");
      detailText = `in ${plural(summary.sealedSecrets, "SealedSecret")}`;
      detail = detailText;
      break;
    case "atLeast":
      primary = `At least ${plural(summary.values, "value")}`;
      detailText = notCountedText(summary.uncounted);
      detail = <NotCounted ids={summary.uncounted} />;
      break;
    case "unknown":
      primary = "Unknown";
      detailText = notCountedText(summary.uncounted);
      detail = <NotCounted ids={summary.uncounted} />;
      break;
  }
  return (
    <button
      type="button"
      aria-label={detailText ? `${primary}, ${detailText}` : undefined}
      aria-expanded={expanded}
      aria-controls={expanded ? detailId : undefined}
      onClick={onToggle}
      className="-mx-2 -my-1 inline-flex items-start gap-1 rounded-md px-2 py-1 text-right transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
    >
      <span className="flex flex-col items-end">
        <span
          className={cn(
            "whitespace-nowrap tabular-nums",
            summary.kind === "unknown" && "text-muted-foreground",
          )}
        >
          {primary}
        </span>
        {detail && (
          <span className="text-xs whitespace-nowrap text-muted-foreground">
            {detail}
          </span>
        )}
      </span>
      <ChevronDown
        className={cn(
          "mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-transform",
          !expanded && "-rotate-90",
        )}
        aria-hidden="true"
      />
    </button>
  );
}

/**
 * A key's references per cluster, in the row under the key's: what each
 * cluster counted and when, then the clusters that did not count and why.
 * It stays in view when the key table scrolls sideways on a phone.
 */
export function ReferencesDetail({
  fleetKey,
  agents,
  now,
}: {
  fleetKey: FleetKey;
  agents: FleetAgent[];
  now: Date;
}) {
  const refs = fleetKey.references;
  const counted = refs.clusters ?? [];
  const uncounted = refs.uncounted ?? [];
  const byId = new Map(agents.map((a) => [a.id, a]));
  return (
    // sticky: the table may be scrolled sideways to reach the button
    <div className="sticky left-4 w-fit max-w-[calc(100vw-4rem)] space-y-3 sm:max-w-2xl">
      {counted.length > 0 && (
        <Table containerClassName="shadow-none" className="w-auto">
          <caption className="sr-only">
            References to key {shortFingerprint(fleetKey.fingerprint)} per
            cluster
          </caption>
          <TableHeader>
            <tr>
              <TableHead className="py-2">Cluster</TableHead>
              <TableHead className="py-2 text-right">Values</TableHead>
              <TableHead className="py-2 text-right">SealedSecrets</TableHead>
              <TableHead className="py-2">Counted</TableHead>
            </tr>
          </TableHeader>
          <tbody>
            {counted.map((c) => (
              <TableRow key={c.agent}>
                <th
                  scope="row"
                  className="px-4 py-2 text-left font-normal whitespace-nowrap"
                >
                  <code className="font-mono font-medium">{c.agent}</code>
                  {c.cluster && c.cluster !== c.agent && (
                    <span className="ml-2 text-xs text-muted-foreground">
                      {c.cluster}
                    </span>
                  )}
                </th>
                <TableCell className="py-2 text-right tabular-nums">
                  {c.values}
                </TableCell>
                <TableCell className="py-2 text-right tabular-nums">
                  {c.sealed_secrets}
                </TableCell>
                <TableCell className="py-2 whitespace-nowrap text-muted-foreground">
                  <RelativeTime
                    iso={c.counted_at}
                    now={now}
                    past
                    describe={(at) => `Counted ${at}`}
                  />
                </TableCell>
              </TableRow>
            ))}
          </tbody>
        </Table>
      )}
      {uncounted.length > 0 && (
        <div className="space-y-1 text-sm">
          <p className="text-foreground">
            {counted.length === 0 || refs.values === 0
              ? "These clusters did not count, so the count is unknown:"
              : "These clusters did not count, so there may be more:"}
          </p>
          <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
            {uncounted.map((id) => (
              <li key={id}>
                <code className="font-mono text-foreground">{id}</code>:{" "}
                {uncountedReason(byId.get(id), now)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
