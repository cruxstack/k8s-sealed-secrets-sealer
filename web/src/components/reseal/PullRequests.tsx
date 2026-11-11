import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ExternalLink, GitPullRequest } from "lucide-react";
import { extractApiError } from "@/api/client";
import {
  resealPullRequestsQueryOptions,
  type PullRequestFilter,
} from "@/api/queries/reseal";
import type { ResealPullRequest } from "@/api/types";
import { plural } from "@/components/fleet/references";
import { Alert } from "@/components/ui/alert";
import { EmptyState } from "@/components/ui/empty-state";
import { RelativeTime } from "@/components/ui/relative-time";
import { SectionHeading } from "@/components/ui/section-heading";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useEnv } from "@/lib/env";
import { cn, safeHttpUrl, sentence } from "@/lib/utils";
import { daysBetween } from "./format";
import { Fingerprints, PullRequestStateBadge } from "./status";

/** An open reseal pull request this many days old needs a look. */
export const LONG_OPEN_DAYS = 7;

const FILTERS: { value: PullRequestFilter; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "merged", label: "Merged" },
  { value: "closed", label: "Closed" },
  { value: "all", label: "All" },
];

/** Which pull requests to list, as pressed toggles. */
function StateFilter({
  value,
  onChange,
}: {
  value: PullRequestFilter;
  onChange: (value: PullRequestFilter) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Pull requests to show"
      className="flex items-center gap-1"
    >
      {FILTERS.map((f) => {
        const on = f.value === value;
        return (
          <button
            key={f.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(f.value)}
            className={cn(
              "inline-flex h-7 items-center rounded-md border px-2.5 text-xs transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
              on
                ? "border-primary bg-selected font-medium text-primary"
                : "border-input bg-card text-foreground hover:bg-muted",
            )}
          >
            {f.label}
          </button>
        );
      })}
    </div>
  );
}

/** "3 open", "1 merged", "4 pull requests": the section's count. */
function countText(filter: PullRequestFilter, n: number): string {
  return filter === "all" ? plural(n, "pull request") : `${n} ${filter}`;
}

const EMPTY: Record<PullRequestFilter, string> = {
  open: "No open reseal pull requests",
  merged: "No merged reseal pull requests",
  closed: "No closed reseal pull requests",
  all: "No reseal pull requests",
};

/**
 * Open ones oldest first, as a queue: what has waited longest comes first.
 * Merged and closed ones newest first.
 */
function sorted(
  prs: ResealPullRequest[],
  filter: PullRequestFilter,
): ResealPullRequest[] {
  const at = (pr: ResealPullRequest) => new Date(pr.opened_at).getTime();
  return [...prs].sort((a, b) =>
    filter === "open" ? at(a) - at(b) : at(b) - at(a),
  );
}

/** Who a pull request is from: its schedule (opening its run), or a user. */
function Source({ pr }: { pr: ResealPullRequest }) {
  const env = useEnv()?.name ?? "";
  if (pr.source === "session") {
    return (
      <span className="flex flex-col">
        <span className="font-medium">{pr.requested_by}</span>
        <span className="text-xs text-muted-foreground">Session</span>
      </span>
    );
  }
  const name = pr.schedule_name ?? "A schedule";
  return (
    <span className="flex flex-col" title={`Requested by ${pr.requested_by}`}>
      {pr.schedule_id ? (
        <Link
          to="/$env/reseal"
          params={{ env }}
          search={(prev) => ({
            ...prev,
            schedule: pr.schedule_id,
            run: pr.run_id,
          })}
          className="w-fit font-medium text-primary hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-label={`${name}: show its run`}
        >
          {name}
        </Link>
      ) : (
        <span className="font-medium">{name}</span>
      )}
      <span className="text-xs text-muted-foreground">Schedule</span>
    </span>
  );
}

/** When it opened, and how long it has been open when that is long. */
function Opened({ pr, now }: { pr: ResealPullRequest; now: Date }) {
  const days = daysBetween(pr.opened_at, now);
  return (
    <span className="flex flex-col whitespace-nowrap">
      <RelativeTime
        iso={pr.opened_at}
        now={now}
        past
        describe={(at) => `Opened ${at}`}
      />
      {pr.state === "open" && days >= LONG_OPEN_DAYS && (
        // a count that needs attention is amber
        <span className="text-xs text-warning">open {days} days</span>
      )}
    </span>
  );
}

/** Its state, and when it merged or closed. */
function State({ pr, now }: { pr: ResealPullRequest; now: Date }) {
  const at = pr.state === "merged" ? pr.merged_at : pr.closed_at;
  return (
    <span className="flex flex-col items-start gap-0.5">
      <PullRequestStateBadge state={pr.state} />
      {pr.state !== "open" && at && (
        <span className="text-xs whitespace-nowrap text-muted-foreground">
          <RelativeTime
            iso={at}
            now={now}
            past
            describe={(abs) =>
              `${pr.state === "merged" ? "Merged" : "Closed"} ${abs}`
            }
          />
        </span>
      )}
    </span>
  );
}

function PullRequestRow({ pr, now }: { pr: ResealPullRequest; now: Date }) {
  const url = safeHttpUrl(pr.url);
  // the icon stays with the title's last word rather than wrapping alone
  const words = pr.title.split(" ");
  const last = words.pop() ?? "";
  const title = (
    <>
      <span className="font-medium text-primary tabular-nums">
        #{pr.number}
      </span>{" "}
      <span className="text-foreground">
        {words.length > 0 && `${words.join(" ")} `}
        <span className="whitespace-nowrap">
          {last}
          {url && (
            <ExternalLink
              className="ml-1 inline h-3 w-3 align-baseline text-muted-foreground"
              aria-hidden="true"
            />
          )}
        </span>
      </span>
    </>
  );
  return (
    <TableRow>
      <th
        scope="row"
        className="px-4 py-3 text-left font-mono text-[13px] font-medium whitespace-nowrap"
      >
        {pr.repo}
      </th>
      <TableCell className="min-w-56">
        {url ? (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            title={`${pr.title}\nBranch ${pr.branch}`}
            className="line-clamp-2 max-w-sm rounded-sm hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            {title}
            <span className="sr-only"> (opens in a new tab)</span>
          </a>
        ) : (
          <span className="line-clamp-2 max-w-sm">{title}</span>
        )}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <Source pr={pr} />
      </TableCell>
      <TableCell className="text-right whitespace-nowrap tabular-nums">
        <span className="flex flex-col items-end">
          <span>{plural(pr.values, "value")}</span>
          <span className="text-xs text-muted-foreground">
            in {plural(pr.files, "file")}
          </span>
        </span>
      </TableCell>
      <TableCell>
        <Fingerprints values={pr.from_keys} />
      </TableCell>
      <TableCell>
        <Opened pr={pr} now={now} />
      </TableCell>
      <TableCell>
        <State pr={pr} now={now} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-muted-foreground">
        <RelativeTime
          iso={pr.checked_at}
          now={now}
          past
          describe={(at) => `State read from GitHub ${at}`}
        />
      </TableCell>
    </TableRow>
  );
}

/** The pull requests left out because the viewer cannot read their repos. */
function hiddenText(hidden: number, listed: number): string {
  if (listed === 0) {
    return hidden === 1
      ? "1 is in a repository you can't read, so it isn't listed."
      : `${hidden} are in repositories you can't read, so they aren't listed.`;
  }
  return hidden === 1
    ? "1 more is in a repository you can't read."
    : `${hidden} more are in repositories you can't read.`;
}

/**
 * Every pull request that moves values onto the env key, like a
 * maintenance queue: the open ones by default, oldest first, with merged
 * and closed ones a filter away. Only those in repositories the viewer can
 * read are listed; the rest are counted.
 */
export function PullRequestSection({
  filter,
  onFilterChange,
  now = new Date(),
}: {
  filter: PullRequestFilter;
  onFilterChange: (filter: PullRequestFilter) => void;
  now?: Date;
}) {
  const { data, error, isPending } = useQuery(
    resealPullRequestsQueryOptions(filter),
  );
  const prs = data ? sorted(data.pull_requests, filter) : [];
  const hidden = data?.hidden ?? 0;

  return (
    <section aria-labelledby="reseal-prs-heading" className="space-y-3">
      <SectionHeading
        id="reseal-prs-heading"
        title="Reseal pull requests"
        count={data ? countText(filter, prs.length) : undefined}
        aside={
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span>Refreshes every minute</span>
            <StateFilter value={filter} onChange={onFilterChange} />
          </div>
        }
      />
      {isPending ? (
        <Skeleton
          className="h-40 w-full"
          aria-busy="true"
          aria-label="Loading reseal pull requests"
        />
      ) : error && !data ? (
        <Alert
          variant="destructive"
          role="alert"
          heading="Could not load the reseal pull requests"
        >
          {sentence(extractApiError(error))}
        </Alert>
      ) : prs.length === 0 ? (
        <EmptyState icon={GitPullRequest} title={EMPTY[filter]}>
          {filter === "open" || filter === "all"
            ? "Runs open one in each repository with values to move, and so does a session with resealed values. They stay here until they merge or close."
            : "Merged and closed ones are kept for 180 days."}
          {hidden > 0 && <> {hiddenText(hidden, 0)}</>}
        </EmptyState>
      ) : (
        <>
          <Table className="[&_td]:align-middle [&_th]:align-middle">
            <caption className="sr-only">Reseal pull requests</caption>
            <TableHeader>
              <tr>
                <TableHead>Repository</TableHead>
                <TableHead>Pull request</TableHead>
                <TableHead>Source</TableHead>
                <TableHead className="text-right">Values</TableHead>
                <TableHead>From keys</TableHead>
                <TableHead>Opened</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Checked</TableHead>
              </tr>
            </TableHeader>
            <tbody>
              {prs.map((pr) => (
                <PullRequestRow
                  key={`${pr.repo}#${pr.number}`}
                  pr={pr}
                  now={now}
                />
              ))}
            </tbody>
          </Table>
          {hidden > 0 && (
            <p className="text-xs text-muted-foreground">
              {hiddenText(hidden, prs.length)}
            </p>
          )}
        </>
      )}
    </section>
  );
}
