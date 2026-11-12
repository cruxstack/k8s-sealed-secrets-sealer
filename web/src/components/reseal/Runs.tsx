import { useEffect, useId, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, CircleStop, ExternalLink, History } from "lucide-react";
import { toast } from "sonner";
import { extractApiError, toApiError } from "@/api/client";
import {
  ACTIVE_REFRESH_MS,
  RESEAL_KEY,
  cancelRun,
  resealRunQueryOptions,
  resealRunsQueryOptions,
  resealSchedulesQueryOptions,
  runActive,
  runsRefreshMs,
} from "@/api/queries/reseal";
import type {
  ResealCounts,
  ResealRunRepo,
  ResealRunSummary,
} from "@/api/types";
import { Confirm, Point, Points } from "@/components/fleet/KeyDialogs";
import { plural } from "@/components/fleet/references";
import { Alert } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { IconButton } from "@/components/ui/icon-button";
import { RegionTag } from "@/components/ui/region-tag";
import { RelativeTime } from "@/components/ui/relative-time";
import { SectionHeading } from "@/components/ui/section-heading";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dash,
  Table,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn, safeHttpUrl, sentence } from "@/lib/utils";
import { formatDuration } from "./format";
import { Progress, RepoStatusBadge, RunStatusBadge } from "./status";

/** The columns of the run table, for the row under a run that spans them. */
const COLUMNS = 9;

/** How long a run took, or has taken so far. */
function Duration({ run, now }: { run: ResealRunSummary; now: Date }) {
  const started = new Date(run.started_at).getTime();
  if (run.finished_at) {
    return <>{formatDuration(new Date(run.finished_at).getTime() - started)}</>;
  }
  if (runActive(run)) {
    return (
      <span className="text-muted-foreground">
        {formatDuration(now.getTime() - started)} so far
      </span>
    );
  }
  return <Dash />;
}

/** Repositories done of all, with a bar while it runs. */
function Repositories({ run }: { run: ResealRunSummary }) {
  const { done, total, hidden } = run.repos;
  if (total === 0) {
    return runActive(run) ? (
      <span className="text-xs text-muted-foreground">Finding them…</span>
    ) : (
      <Dash />
    );
  }
  return (
    <span
      className="flex flex-col items-end gap-1"
      title={
        hidden > 0
          ? `${plural(hidden, "of them is", "of them are")} in repositories you can't read`
          : undefined
      }
    >
      <span className="tabular-nums">
        {done} of {total}
      </span>
      {runActive(run) && (
        <Progress
          done={done}
          total={total}
          label={`Repositories done in the run of ${run.schedule_name}`}
          className="w-20"
        />
      )}
    </span>
  );
}

/** Values resealed, then those already current and those that failed. */
function Values({ values }: { values: ResealCounts }) {
  return (
    <span className="flex flex-col items-end whitespace-nowrap tabular-nums">
      <span>{values.resealed} resealed</span>
      <span className="text-xs text-muted-foreground">
        {values.current} current
      </span>
      {values.failed > 0 && (
        <span className="text-xs text-destructive">{values.failed} failed</span>
      )}
    </span>
  );
}

/** "3 resealed, 10 current, 1 failed", for a repository's row. */
function valuesText(values: ResealCounts): string {
  const parts = [`${values.resealed} resealed`, `${values.current} current`];
  if (values.failed > 0) parts.push(`${values.failed} failed`);
  return parts.join(", ");
}

/** The values a repository could not reseal: where each is and why. */
function Failures({ repo }: { repo: ResealRunRepo }) {
  const failures = repo.failures ?? [];
  const unlisted = repo.values.failed - failures.length;
  return (
    <div className="space-y-1.5">
      <Table
        containerClassName="w-fit max-w-full shadow-none"
        className="w-auto"
      >
        <caption className="sr-only">
          Values that could not be resealed in {repo.repo}
        </caption>
        <TableHeader>
          <tr>
            <TableHead className="py-2">Path</TableHead>
            <TableHead className="py-2">Key</TableHead>
            <TableHead className="py-2 text-right">Document</TableHead>
            <TableHead className="py-2">Region</TableHead>
            <TableHead className="py-2">Error</TableHead>
          </tr>
        </TableHeader>
        <tbody>
          {failures.map((f, i) => (
            <TableRow key={`${f.path}:${f.document}:${f.key}:${i}`}>
              <th
                scope="row"
                className="px-4 py-2 text-left font-mono text-xs font-normal whitespace-nowrap"
              >
                {f.path}
              </th>
              <TableCell className="py-2 font-mono text-xs font-medium whitespace-nowrap">
                {f.key}
              </TableCell>
              <TableCell className="py-2 text-right tabular-nums">
                #{f.document}
              </TableCell>
              <TableCell className="py-2">
                {f.region ? <RegionTag region={f.region} /> : <Dash />}
              </TableCell>
              <TableCell className="min-w-56 py-2 text-destructive">
                {sentence(f.error)}
              </TableCell>
            </TableRow>
          ))}
        </tbody>
      </Table>
      {unlisted > 0 && (
        <p className="text-xs text-muted-foreground">
          {plural(unlisted, "more value", "more values")} failed; only the first{" "}
          {failures.length} are listed.
        </p>
      )}
    </div>
  );
}

/** One repository of a run: how it went, its pull request, and why. */
function RepoRow({ repo }: { repo: ResealRunRepo }) {
  const url = safeHttpUrl(repo.pull_request?.url);
  const failures = repo.failures ?? [];
  return (
    <>
      <TableRow className={cn(failures.length > 0 && "border-b-0")}>
        <th
          scope="row"
          className="px-4 py-2 text-left font-mono text-xs font-medium whitespace-nowrap"
        >
          {repo.repo}
        </th>
        <TableCell className="py-2">
          <RepoStatusBadge status={repo.status} />
        </TableCell>
        <TableCell className="py-2 text-right tabular-nums">
          {repo.files}
        </TableCell>
        <TableCell className="py-2 whitespace-nowrap tabular-nums">
          {repo.values.resealed + repo.values.current + repo.values.failed >
          0 ? (
            valuesText(repo.values)
          ) : (
            <Dash />
          )}
        </TableCell>
        <TableCell className="py-2 whitespace-nowrap">
          {repo.pull_request ? (
            url ? (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-primary hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                #{repo.pull_request.number}
                <ExternalLink className="h-3 w-3" aria-hidden="true" />
                <span className="sr-only"> (opens in a new tab)</span>
              </a>
            ) : (
              `#${repo.pull_request.number}`
            )
          ) : (
            <Dash />
          )}
        </TableCell>
        <TableCell className="min-w-48 py-2 text-muted-foreground">
          {repo.reason ? sentence(repo.reason) : <Dash />}
        </TableCell>
      </TableRow>
      {failures.length > 0 && (
        <TableRow>
          <td colSpan={6} className="px-4 pt-0 pb-3">
            <Failures repo={repo} />
          </td>
        </TableRow>
      )}
    </>
  );
}

/** "2 more are in repositories you can't read." */
function hiddenRepos(hidden: number, listed: number): string {
  if (listed === 0) {
    return hidden === 1
      ? "Its one repository is one you can't read."
      : `All ${hidden} of its repositories are ones you can't read.`;
  }
  return hidden === 1
    ? "1 more is a repository you can't read."
    : `${hidden} more are repositories you can't read.`;
}

/**
 * A run's detail, in the row under it: what it did in each repository the
 * viewer can read, with the values that failed. It refreshes while the run
 * is active.
 */
function RunDetail({ id }: { id: string }) {
  const { data, error, isPending } = useQuery(resealRunQueryOptions(id));
  if (isPending) {
    return (
      <Skeleton
        className="h-20 w-full max-w-xl"
        aria-busy="true"
        aria-label="Loading the run"
      />
    );
  }
  if (error && !data) {
    return (
      <Alert variant="destructive" role="alert">
        Could not load the run: {sentence(extractApiError(error))}
      </Alert>
    );
  }
  const repos = data.repositories;
  const hidden = data.repos.hidden;
  return (
    <div className="space-y-3">
      {data.error && (
        <Alert variant="destructive" role="status">
          {sentence(data.error)}
        </Alert>
      )}
      {repos.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {hidden > 0
            ? hiddenRepos(hidden, 0)
            : runActive(data)
              ? "It is finding the repositories in its scope."
              : "It found no repository in its scope."}
        </p>
      ) : (
        <Table
          containerClassName="w-fit max-w-full shadow-none"
          className="w-auto"
        >
          <caption className="sr-only">
            Repositories in the run of {data.schedule_name}
          </caption>
          <TableHeader>
            <tr>
              <TableHead className="py-2">Repository</TableHead>
              <TableHead className="py-2">Status</TableHead>
              <TableHead className="py-2 text-right">Files</TableHead>
              <TableHead className="py-2">Values</TableHead>
              <TableHead className="py-2">Pull Request</TableHead>
              <TableHead className="py-2">Reason</TableHead>
            </tr>
          </TableHeader>
          <tbody>
            {repos.map((r) => (
              <RepoRow key={r.repo} repo={r} />
            ))}
          </tbody>
        </Table>
      )}
      {hidden > 0 && repos.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {hiddenRepos(hidden, repos.length)}
        </p>
      )}
    </div>
  );
}

function RunRow({
  run,
  now,
  expanded,
  cancelling,
  onToggle,
  onCancel,
}: {
  run: ResealRunSummary;
  now: Date;
  expanded: boolean;
  cancelling: boolean;
  onToggle: () => void;
  onCancel: () => void;
}) {
  const detailId = useId();
  const active = runActive(run);
  return (
    <>
      <TableRow id={`run-${run.id}`} className={cn(expanded && "border-b-0")}>
        <th scope="row" className="px-4 py-3 text-left font-normal">
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={expanded ? detailId : undefined}
            onClick={onToggle}
            className="-mx-2 -my-1 inline-flex items-center gap-1 rounded-md px-2 py-1 text-left transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            <ChevronDown
              className={cn(
                "h-4 w-4 shrink-0 text-muted-foreground transition-transform",
                !expanded && "-rotate-90",
              )}
              aria-hidden="true"
            />
            <span className="font-medium whitespace-nowrap">
              {run.schedule_name}
            </span>
          </button>
        </th>
        <TableCell>
          <span className="flex flex-col items-start gap-0.5">
            <RunStatusBadge status={run.status} />
            {run.error && (
              <span
                className="line-clamp-1 max-w-48 text-xs text-destructive"
                title={sentence(run.error)}
              >
                {sentence(run.error)}
              </span>
            )}
          </span>
        </TableCell>
        <TableCell className="whitespace-nowrap">
          {run.trigger === "manual" ? (
            <span className="flex flex-col">
              <span>Run Now</span>
              <span className="text-xs text-muted-foreground">
                by {run.requested_by}
              </span>
            </span>
          ) : (
            "Scheduled"
          )}
        </TableCell>
        <TableCell className="whitespace-nowrap">
          <RelativeTime
            iso={run.started_at}
            now={now}
            past
            describe={(at) => `Started ${at}`}
          />
        </TableCell>
        <TableCell className="whitespace-nowrap tabular-nums">
          <Duration run={run} now={now} />
        </TableCell>
        <TableCell className="text-right whitespace-nowrap">
          <Repositories run={run} />
        </TableCell>
        <TableCell className="text-right">
          <Values values={run.values} />
        </TableCell>
        <TableCell className="text-right tabular-nums">
          {run.pull_requests}
        </TableCell>
        <TableCell className="py-2 text-right whitespace-nowrap">
          <IconButton
            label="Cancel"
            reason={
              cancelling
                ? "Cancelling…"
                : active
                  ? undefined
                  : "Only a queued or running run can be cancelled."
            }
            aria-label={`Cancel the run of ${run.schedule_name}`}
            className={cn(
              "text-muted-foreground",
              active &&
                !cancelling &&
                "hover:text-destructive focus-visible:text-destructive",
            )}
            onClick={onCancel}
          >
            <CircleStop className="h-4 w-4" aria-hidden="true" />
          </IconButton>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow id={detailId} className="bg-muted/30">
          <td colSpan={COLUMNS} className="px-4 py-3">
            {/* sticky: the table may be scrolled sideways to reach the
                button */}
            <div className="sticky left-4 w-fit max-w-[calc(100vw-4rem)] lg:max-w-5xl">
              <RunDetail id={run.id} />
            </div>
          </td>
        </TableRow>
      )}
    </>
  );
}

/** What cancelling a run does, before it is confirmed. */
function CancelRunDialog({
  run,
  request,
  now,
  onConfirm,
}: {
  run: ResealRunSummary;
  request: { isPending: boolean; error: Error | null };
  now: Date;
  onConfirm: () => void;
}) {
  return (
    <>
      <DialogHeader>
        <DialogTitle>Cancel This Run?</DialogTitle>
        <DialogDescription>
          The run of{" "}
          <span className="font-medium text-foreground">
            {run.schedule_name}
          </span>{" "}
          that started{" "}
          <RelativeTime
            iso={run.started_at}
            now={now}
            past
            describe={(at) => `Started ${at}`}
          />{" "}
          stops.
        </DialogDescription>
      </DialogHeader>
      <Points>
        <Point lead="It queues nothing more.">
          What it already sent to agents expires within 10 minutes.
        </Point>
        <Point>Pull requests it already opened stay open.</Point>
        <Point>
          Repositories it did not finish are left as they are; the next run
          reseals them.
        </Point>
      </Points>
      <Confirm
        request={request}
        failed="cancel the run"
        label="Cancel Run"
        dismiss="Keep Running"
        destructive
        onConfirm={onConfirm}
      />
    </>
  );
}

/** Which schedule's runs to list. */
function ScheduleFilter({
  value,
  runs,
  onChange,
}: {
  value?: string;
  runs: ResealRunSummary[];
  onChange: (id: string | undefined) => void;
}) {
  const id = useId();
  const { data: schedules } = useQuery(resealSchedulesQueryOptions);
  const options = (schedules ?? []).map((s) => ({ id: s.id, name: s.name }));
  // a deleted schedule's runs are still listed by name
  if (value && !options.some((o) => o.id === value)) {
    options.push({
      id: value,
      name:
        runs.find((r) => r.schedule_id === value)?.schedule_name ??
        "Deleted Schedule",
    });
  }
  return (
    <span className="flex items-center gap-1.5">
      <label htmlFor={id}>Schedule</label>
      <select
        id={id}
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value || undefined)}
        className="h-8 max-w-48 rounded-md border border-input bg-card px-2 text-xs text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <option value="">All Schedules</option>
        {options.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
          </option>
        ))}
      </select>
    </span>
  );
}

/** "12 runs, 1 running": the section's count. */
function runCount(runs: ResealRunSummary[]): string {
  const active = runs.filter(runActive).length;
  const all = plural(runs.length, "run");
  return active > 0 ? `${all}, ${active} running` : all;
}

/**
 * The latest runs, newest first: every schedule's, or the one picked. A
 * run opens in a row under it with what it did in each repository; an
 * active one shows its progress, refreshes, and can be cancelled.
 */
export function RunSection({
  scheduleId,
  openRun,
  onScheduleChange,
  onToggleRun,
  now = new Date(),
}: {
  scheduleId?: string;
  /** The run whose detail is open. */
  openRun?: string;
  onScheduleChange: (id: string | undefined) => void;
  onToggleRun: (id: string | undefined) => void;
  now?: Date;
}) {
  const queryClient = useQueryClient();
  const { data, error, isPending } = useQuery(
    resealRunsQueryOptions(scheduleId),
  );
  const [cancelling, setCancelling] = useState<ResealRunSummary | null>(null);
  const cancel = useMutation({
    mutationFn: (run: ResealRunSummary) => cancelRun(run.id),
    onSuccess: (_, run) => {
      setCancelling(null);
      toast.success(`Cancelled the run of ${run.schedule_name}`, {
        description: "Pull requests it opened stay open.",
      });
    },
    // in flight until the list shows it cancelled, so its icon can't
    // be used twice in between
    onSettled: () => queryClient.invalidateQueries({ queryKey: RESEAL_KEY }),
  });
  const latest = data ?? [];
  // a run a link opens that the list doesn't hold (older than its latest,
  // or another schedule's) is read on its own and shown last
  const linked = useQuery({
    ...resealRunQueryOptions(openRun ?? ""),
    enabled:
      openRun !== undefined &&
      data !== undefined &&
      !latest.some((r) => r.id === openRun),
  });
  const extra =
    linked.data && !latest.some((r) => r.id === linked.data.id)
      ? [linked.data]
      : [];
  const runs = [...latest, ...extra];
  const listed = runs.some((r) => r.id === openRun);
  const linkFailed =
    openRun !== undefined && !listed && linked.error ? linked.error : null;

  // a link to a run (from a pull request, or a schedule's last run) shows it
  useEffect(() => {
    if (openRun && listed) {
      document
        .getElementById(`run-${openRun}`)
        ?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
  }, [openRun, listed]);

  return (
    <section aria-labelledby="reseal-runs-heading" className="space-y-3">
      <SectionHeading
        id="reseal-runs-heading"
        title="Runs"
        count={data ? runCount(runs) : undefined}
        aside={
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span>
              {runsRefreshMs(data) === ACTIVE_REFRESH_MS
                ? "Refreshes every 10 seconds"
                : "Refreshes every minute"}
            </span>
            <ScheduleFilter
              value={scheduleId}
              runs={runs}
              onChange={onScheduleChange}
            />
          </div>
        }
      />
      {linkFailed && (
        <Alert variant="info" role="status">
          {toApiError(linkFailed).status === 404
            ? "The run this link opens isn't kept any more: runs are kept for 180 days after they finish."
            : `Could not load the run this link opens: ${sentence(extractApiError(linkFailed))}`}
        </Alert>
      )}
      {isPending ? (
        <Skeleton
          className="h-40 w-full"
          aria-busy="true"
          aria-label="Loading runs"
        />
      ) : error && !data ? (
        <Alert
          variant="destructive"
          role="alert"
          heading="Could Not Load the Runs"
        >
          {sentence(extractApiError(error))}
        </Alert>
      ) : runs.length === 0 ? (
        <EmptyState
          icon={History}
          title={scheduleId ? "No Runs of This Schedule Yet" : "No Runs Yet"}
        >
          A schedule runs when it comes due, or when you start one with Run Now.
        </EmptyState>
      ) : (
        <Table className="[&_td]:align-middle [&_th]:align-middle">
          <caption className="sr-only">Reseal runs, newest first</caption>
          <TableHeader>
            <tr>
              <TableHead>Schedule</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Trigger</TableHead>
              <TableHead>Started</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead className="text-right">Repositories</TableHead>
              <TableHead className="text-right">Values</TableHead>
              <TableHead className="text-right">PRs</TableHead>
              <TableHead className="w-px text-right">Actions</TableHead>
            </tr>
          </TableHeader>
          <tbody>
            {runs.map((run) => (
              <RunRow
                key={run.id}
                run={run}
                now={now}
                expanded={run.id === openRun}
                cancelling={cancel.isPending && cancel.variables?.id === run.id}
                onToggle={() =>
                  onToggleRun(run.id === openRun ? undefined : run.id)
                }
                onCancel={() => {
                  cancel.reset();
                  setCancelling(run);
                }}
              />
            ))}
          </tbody>
        </Table>
      )}

      <Dialog
        open={cancelling !== null}
        onOpenChange={(o) => !o && !cancel.isPending && setCancelling(null)}
      >
        <DialogContent>
          {cancelling && (
            <CancelRunDialog
              run={cancelling}
              request={cancel}
              now={now}
              onConfirm={() => cancel.mutate(cancelling)}
            />
          )}
        </DialogContent>
      </Dialog>
    </section>
  );
}
