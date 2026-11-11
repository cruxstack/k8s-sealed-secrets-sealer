import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  CalendarClock,
  CirclePause,
  CirclePlay,
  Pencil,
  Play,
  Plus,
  Trash2,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { extractApiError } from "@/api/client";
import {
  RESEAL_KEY,
  deleteSchedule,
  resealSchedulesQueryOptions,
  runActive,
  runSchedule,
  updateSchedule,
} from "@/api/queries/reseal";
import type { ResealSchedule } from "@/api/types";
import { Confirm, Point, Points } from "@/components/fleet/KeyDialogs";
import { plural } from "@/components/fleet/references";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { IconButton } from "@/components/ui/icon-button";
import { ReasonButton } from "@/components/ui/reason-button";
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
import { cn, relativeTime, sentence } from "@/lib/utils";
import { LIMITS, intervalApprox } from "./format";
import { ScheduleDialog } from "./ScheduleDialog";
import { Progress, RunStatusBadge, ScopeChips } from "./status";

type ScheduleAction = "run" | "edit" | "toggle" | "delete";

/**
 * Why Run now cannot start a run of a schedule now, or undefined when it
 * can: one run at a time, and only while values can be resealed.
 */
export function runNowReason(
  schedule: ResealSchedule,
  resealBlocked: string | undefined,
): string | undefined {
  if (schedule.active_run_id) {
    return "A run is in progress. Wait for it to finish, or cancel it under Runs.";
  }
  return resealBlocked;
}

/**
 * Run now, Edit, Pause or Resume, and Delete, as icons in the same places
 * on every schedule's row; Run now is grayed out with the reason when it
 * cannot start a run.
 */
function ScheduleActions({
  schedule,
  runReason,
  busy,
  onAction,
}: {
  schedule: ResealSchedule;
  runReason?: string;
  /** The action whose request for this schedule is in flight. */
  busy?: ScheduleAction;
  onAction: (action: ScheduleAction) => void;
}) {
  const name = schedule.name;
  const toggle = schedule.enabled ? "Pause" : "Resume";
  return (
    <span className="inline-flex items-center gap-1">
      <IconButton
        label="Run now"
        reason={busy === "run" ? "Starting a run…" : runReason}
        aria-label={`Run ${name} now`}
        className="text-muted-foreground"
        onClick={() => onAction("run")}
      >
        <Play className="h-4 w-4" aria-hidden="true" />
      </IconButton>
      <IconButton
        label="Edit"
        aria-label={`Edit ${name}`}
        className="text-muted-foreground"
        onClick={() => onAction("edit")}
      >
        <Pencil className="h-4 w-4" aria-hidden="true" />
      </IconButton>
      <IconButton
        label={toggle}
        reason={busy === "toggle" ? "Saving…" : undefined}
        aria-label={`${toggle} ${name}`}
        className="text-muted-foreground"
        onClick={() => onAction("toggle")}
      >
        {schedule.enabled ? (
          <CirclePause className="h-4 w-4" aria-hidden="true" />
        ) : (
          <CirclePlay className="h-4 w-4" aria-hidden="true" />
        )}
      </IconButton>
      <IconButton
        label="Delete"
        aria-label={`Delete ${name}`}
        className="text-muted-foreground hover:text-destructive focus-visible:text-destructive"
        onClick={() => onAction("delete")}
      >
        <Trash2 className="h-4 w-4" aria-hidden="true" />
      </IconButton>
    </span>
  );
}

/** When it runs next: paused, due, or a relative time. */
function NextRun({ schedule, now }: { schedule: ResealSchedule; now: Date }) {
  if (!schedule.enabled || !schedule.next_run_at) {
    return <span className="text-muted-foreground">Paused</span>;
  }
  if (new Date(schedule.next_run_at).getTime() <= now.getTime()) {
    return (
      <span
        title={
          schedule.active_run_id
            ? "Due; it starts once its run in progress finishes"
            : "Due; it starts within a minute"
        }
      >
        Due
      </span>
    );
  }
  return (
    <RelativeTime
      iso={schedule.next_run_at}
      now={now}
      describe={(at) => `Next run ${at}`}
    />
  );
}

/** Its latest run: its status, when, and its progress while it runs. */
function LastRun({ schedule, now }: { schedule: ResealSchedule; now: Date }) {
  const env = useEnv()?.name ?? "";
  const run = schedule.last_run;
  if (!run) return <span className="text-muted-foreground">Never run</span>;
  return (
    <span className="flex flex-col items-start gap-1">
      <span className="flex items-center gap-2 whitespace-nowrap">
        <RunStatusBadge status={run.status} />
        <Link
          to="/$env/reseal"
          params={{ env }}
          search={(prev) => ({ ...prev, schedule: schedule.id, run: run.id })}
          className="text-xs text-primary hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-label={`Show the latest run of ${schedule.name}, started ${relativeTime(run.started_at, now)}`}
        >
          <RelativeTime
            iso={run.started_at}
            now={now}
            past
            describe={(at) => `Started ${at}`}
          />
        </Link>
      </span>
      {runActive(run) && run.repos.total > 0 && (
        <Progress
          done={run.repos.done}
          total={run.repos.total}
          label={`Repositories done in ${schedule.name}'s run`}
          className="w-28"
        />
      )}
    </span>
  );
}

function ScheduleRow({
  schedule,
  now,
  runReason,
  busy,
  onAction,
}: {
  schedule: ResealSchedule;
  now: Date;
  runReason?: string;
  busy?: ScheduleAction;
  onAction: (action: ScheduleAction) => void;
}) {
  const approx = intervalApprox(schedule.interval_days);
  return (
    <TableRow className={cn(!schedule.enabled && "text-muted-foreground")}>
      <th scope="row" className="px-4 py-3 text-left font-normal">
        <span className="flex min-w-32 flex-col">
          <span className="font-medium">{schedule.name}</span>
          <span
            className="text-xs text-muted-foreground"
            title={
              schedule.updated_by
                ? `Last changed by ${schedule.updated_by}`
                : undefined
            }
          >
            by {schedule.created_by}
          </span>
        </span>
      </th>
      <TableCell className="min-w-48">
        <ScopeChips repos={schedule.repos} orgs={schedule.orgs} />
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <span className="flex flex-col">
          <span className="tabular-nums">
            {plural(schedule.interval_days, "day")}
          </span>
          {approx && (
            <span className="text-xs text-muted-foreground">{approx}</span>
          )}
        </span>
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <NextRun schedule={schedule} now={now} />
      </TableCell>
      <TableCell>
        <LastRun schedule={schedule} now={now} />
      </TableCell>
      <TableCell className="py-2 text-right whitespace-nowrap">
        <ScheduleActions
          schedule={schedule}
          runReason={runReason}
          busy={busy}
          onAction={onAction}
        />
      </TableCell>
    </TableRow>
  );
}

/** What deleting a schedule does, before it is confirmed. */
function DeleteScheduleDialog({
  schedule,
  request,
  onConfirm,
}: {
  schedule: ResealSchedule;
  request: { isPending: boolean; error: Error | null };
  onConfirm: () => void;
}) {
  return (
    <>
      <DialogHeader>
        <DialogTitle>Delete this schedule?</DialogTitle>
        <DialogDescription>
          <span className="font-medium text-foreground">{schedule.name}</span>{" "}
          stops running. To stop it for a while instead, pause it.
        </DialogDescription>
      </DialogHeader>
      <Points>
        {schedule.active_run_id && (
          <Point lead="Its run in progress is cancelled.">
            It queues nothing more; what it already sent to agents expires.
          </Point>
        )}
        <Point>
          Pull requests its runs opened stay open, and stay listed here, until
          they merge or close.
        </Point>
      </Points>
      <Confirm
        request={request}
        failed="delete the schedule"
        label="Delete schedule"
        destructive
        onConfirm={onConfirm}
      />
    </>
  );
}

/** "3 schedules, 1 paused": the section's count. */
function scheduleCount(schedules: ResealSchedule[]): string {
  const paused = schedules.filter((s) => !s.enabled).length;
  const all = plural(schedules.length, "schedule");
  return paused > 0 ? `${all}, ${paused} paused` : all;
}

/**
 * The env's schedules: each reseals the values of its repositories, and of
 * every repository of its orgs, every so many days. Admins create, edit,
 * pause, resume and delete them, and start a run now.
 */
export function ScheduleSection({
  resealBlocked,
  now = new Date(),
}: {
  /** Why values cannot be resealed now; unset when they can. */
  resealBlocked?: string;
  now?: Date;
}) {
  const queryClient = useQueryClient();
  const { data, error, isPending } = useQuery(resealSchedulesQueryOptions);
  // the schedule being edited, or {} for a new one
  const [editing, setEditing] = useState<{ schedule?: ResealSchedule } | null>(
    null,
  );
  const [deleting, setDeleting] = useState<ResealSchedule | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  // a request counts as in flight until the lists it changed are read
  // again, so its row can't be acted on twice in between (a second Run
  // now before the schedule shows its run, say)
  const refresh = () => queryClient.invalidateQueries({ queryKey: RESEAL_KEY });
  const run = useMutation({
    mutationFn: (s: ResealSchedule) => runSchedule(s.id),
    onSuccess: (_, s) =>
      toast.success(`Started a run of ${s.name}`, {
        description: "Its progress shows under Runs.",
      }),
    onError: (err, s) =>
      setFailure(
        `Could not start a run of ${s.name}: ${sentence(extractApiError(err))}`,
      ),
    onSettled: refresh,
  });
  const toggle = useMutation({
    mutationFn: (s: ResealSchedule) =>
      updateSchedule(s.id, { enabled: !s.enabled }),
    onSuccess: (updated, s) =>
      toast.success(
        updated.enabled ? `Resumed ${s.name}` : `Paused ${s.name}`,
        {
          description:
            updated.enabled && updated.next_run_at
              ? `Next run ${relativeTime(updated.next_run_at)}.`
              : "It doesn't run until you resume it.",
        },
      ),
    onError: (err, s) =>
      setFailure(
        `Could not ${s.enabled ? "pause" : "resume"} ${s.name}: ${sentence(extractApiError(err))}`,
      ),
    onSettled: refresh,
  });
  const remove = useMutation({
    mutationFn: (s: ResealSchedule) => deleteSchedule(s.id),
    onSuccess: (_, s) => {
      setDeleting(null);
      toast.success(`Deleted ${s.name}`);
    },
    onSettled: refresh,
  });

  const schedules = data ?? [];
  const full = schedules.length >= LIMITS.schedules;
  const busyFor = (s: ResealSchedule): ScheduleAction | undefined =>
    run.isPending && run.variables?.id === s.id
      ? "run"
      : toggle.isPending && toggle.variables?.id === s.id
        ? "toggle"
        : undefined;
  const act = (s: ResealSchedule, action: ScheduleAction) => {
    setFailure(null);
    switch (action) {
      case "run":
        run.mutate(s);
        break;
      case "toggle":
        toggle.mutate(s);
        break;
      case "edit":
        setEditing({ schedule: s });
        break;
      case "delete":
        remove.reset();
        setDeleting(s);
        break;
    }
  };
  const newButton = (
    <ReasonButton
      size="sm"
      reason={
        isPending
          ? "Loading the schedules…"
          : full
            ? `An env has at most ${LIMITS.schedules} schedules. Delete one first.`
            : undefined
      }
      onClick={() => setEditing({})}
    >
      <Plus className="mr-1.5 h-4 w-4" aria-hidden="true" />
      New schedule
    </ReasonButton>
  );

  return (
    <section aria-labelledby="reseal-schedules-heading" className="space-y-3">
      <SectionHeading
        id="reseal-schedules-heading"
        title="Schedules"
        count={data ? scheduleCount(schedules) : undefined}
        aside={newButton}
      />
      {failure && (
        <Alert
          variant="destructive"
          role="alert"
          action={
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              aria-label="Dismiss"
              onClick={() => setFailure(null)}
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </Button>
          }
        >
          {failure}
        </Alert>
      )}
      {isPending ? (
        <Skeleton
          className="h-32 w-full"
          aria-busy="true"
          aria-label="Loading schedules"
        />
      ) : error && !data ? (
        <Alert
          variant="destructive"
          role="alert"
          heading="Could not load the schedules"
        >
          {sentence(extractApiError(error))}
        </Alert>
      ) : schedules.length === 0 ? (
        <EmptyState icon={CalendarClock} title="No schedules">
          A schedule reseals every value in its repositories, and in every
          repository of its orgs, every so many days, with a pull request per
          repository. Create one to keep values on the env key.
        </EmptyState>
      ) : (
        <Table className="[&_td]:align-middle [&_th]:align-middle">
          <caption className="sr-only">Reseal schedules</caption>
          <TableHeader>
            <tr>
              <TableHead>Name</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Every</TableHead>
              <TableHead>Next run</TableHead>
              <TableHead>Last run</TableHead>
              <TableHead className="w-px text-right">Actions</TableHead>
            </tr>
          </TableHeader>
          <tbody>
            {schedules.map((s) => (
              <ScheduleRow
                key={s.id}
                schedule={s}
                now={now}
                runReason={runNowReason(s, resealBlocked)}
                busy={busyFor(s)}
                onAction={(action) => act(s, action)}
              />
            ))}
          </tbody>
        </Table>
      )}

      <ScheduleDialog
        open={editing !== null}
        schedule={editing?.schedule}
        now={now}
        onClose={() => setEditing(null)}
      />

      <Dialog
        open={deleting !== null}
        onOpenChange={(o) => !o && !remove.isPending && setDeleting(null)}
      >
        <DialogContent>
          {deleting && (
            <DeleteScheduleDialog
              schedule={deleting}
              request={remove}
              onConfirm={() => remove.mutate(deleting)}
            />
          )}
        </DialogContent>
      </Dialog>
    </section>
  );
}
