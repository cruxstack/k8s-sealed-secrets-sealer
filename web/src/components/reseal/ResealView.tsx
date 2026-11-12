import { useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { extractApiError } from "@/api/client";
import {
  RESEAL_KEY,
  resealRunsQueryOptions,
  resealSchedulesQueryOptions,
  runActive,
} from "@/api/queries/reseal";
import { statusQueryOptions } from "@/api/queries/status";
import { Alert } from "@/components/ui/alert";
import { useEnv } from "@/lib/env";
import { sentence } from "@/lib/utils";
import { resealBlocked, resealReason } from "./format";
import { PullRequestSection } from "./PullRequests";
import { RunSection } from "./Runs";
import { ScheduleSection } from "./Schedules";
import type { ResealSearch } from "./search";

/**
 * Refreshes the reseal pull requests, and the rest, as soon as a run
 * finishes, since it may have opened some: they would otherwise show up
 * at their next poll, a minute later.
 */
function useRefreshWhenRunsFinish(scheduleId: string | undefined) {
  const queryClient = useQueryClient();
  // the page's own queries, from the cache: no requests of their own
  const { data: schedules } = useQuery(resealSchedulesQueryOptions);
  const { data: runs } = useQuery(resealRunsQueryOptions(scheduleId));
  const active = [
    ...new Set([
      ...(schedules ?? []).flatMap((s) =>
        s.active_run_id ? [s.active_run_id] : [],
      ),
      ...(runs ?? []).filter(runActive).map((r) => r.id),
    ]),
  ]
    .sort()
    .join(" ");
  const previous = useRef(active);
  useEffect(() => {
    const now = new Set(active.split(" "));
    const finished = previous.current
      .split(" ")
      .some((id) => id !== "" && !now.has(id));
    previous.current = active;
    if (finished) void queryClient.invalidateQueries({ queryKey: RESEAL_KEY });
  }, [active, queryClient]);
}

/**
 * The env's resealing, for its admins: the reseal pull requests first, as
 * a queue to merge, then the schedules that open them and their runs.
 */
export function ResealView({
  search,
  onSearchChange,
}: {
  search: ResealSearch;
  onSearchChange: (patch: Partial<ResealSearch>) => void;
}) {
  const env = useEnv()?.name ?? "";
  const { data: status, error: statusError } = useQuery(statusQueryOptions);
  // until the status is known, nothing can start a run
  const blocked = resealReason(status, statusError);
  useRefreshWhenRunsFinish(search.schedule);

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold tracking-tight">Reseal</h1>
        <p className="text-sm text-muted-foreground">
          Moves the values in the{" "}
          <span className="font-medium text-foreground">{env}</span> env's
          repositories onto its env key, through pull requests. Only admins see
          this page.
        </p>
      </header>

      <Alert variant="info" aria-label="What resealing does">
        Resealing re-encrypts values sealed with older keys for the env key.
        Once its pull requests merge and deploy, nothing refers to the old keys,
        and they can be deleted on the{" "}
        <Link
          to="/$env/fleet"
          params={{ env }}
          className="font-medium text-primary hover:underline"
        >
          fleet
        </Link>
        . It doesn't rotate values: git history keeps the old ciphertext, so a
        value sealed with a key that may be exposed still needs a new value.
      </Alert>

      {!status && statusError && (
        <Alert
          variant="warning"
          role="status"
          heading={`Couldn't Check Whether Values Can Be Resealed in ${env}`}
        >
          {sentence(extractApiError(statusError))} Run Now waits until it can
          check; this page asks again every 30 seconds.
        </Alert>
      )}

      {status && !status.can_reseal && (
        <Alert
          variant="warning"
          role="status"
          heading={`Values Can't Be Resealed in ${env} Right Now`}
        >
          {resealBlocked(status)} Run Now, and Reseal All in a repository, are
          unavailable until they can.
        </Alert>
      )}

      <PullRequestSection
        filter={search.prs ?? "open"}
        onFilterChange={(prs) =>
          onSearchChange({ prs: prs === "open" ? undefined : prs })
        }
      />

      <ScheduleSection resealBlocked={blocked} />

      <RunSection
        scheduleId={search.schedule}
        openRun={search.run}
        onScheduleChange={(schedule) =>
          onSearchChange({ schedule, run: undefined })
        }
        onToggleRun={(run) => onSearchChange({ run })}
      />
    </div>
  );
}
