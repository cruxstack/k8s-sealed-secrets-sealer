import { queryOptions } from "@tanstack/react-query";
import apiClient from "@/api/client";
import type {
  ResealPullRequestList,
  ResealPullRequestState,
  ResealRun,
  ResealRunSummary,
  ResealSchedule,
  ResealScheduleInput,
} from "@/api/types";

/**
 * How often schedules and runs refresh: a tick advances runs every minute
 * on Lambda (5 seconds in the local stack), so a running run's progress
 * shows within seconds of it.
 */
export const RESEAL_REFRESH_MS = 10_000;

/**
 * How often reseal pull requests refresh. Ticks read their state from
 * GitHub about every 15 minutes, and the list checks the viewer's access
 * to each repository, so more often would show nothing new.
 */
export const PULL_REQUESTS_REFRESH_MS = 60_000;

/** How many runs the list shows; the API allows up to 50. */
export const RUNS_LIMIT = 25;

/** Every reseal query starts with this, to refresh them all at once. */
export const RESEAL_KEY = ["reseal"] as const;

const schedulePath = (id: string) =>
  `/reseal/schedules/${encodeURIComponent(id)}`;

export const resealSchedulesQueryOptions = queryOptions({
  queryKey: [...RESEAL_KEY, "schedules"],
  queryFn: async () => {
    const { data } = await apiClient.get<{ schedules: ResealSchedule[] }>(
      "/reseal/schedules",
    );
    return data.schedules;
  },
  refetchInterval: RESEAL_REFRESH_MS,
  staleTime: 5_000,
});

/** The latest runs, newest first: every schedule's, or one's. */
export function resealRunsQueryOptions(scheduleId?: string) {
  return queryOptions({
    queryKey: [...RESEAL_KEY, "runs", scheduleId ?? "all"],
    queryFn: async () => {
      const { data } = await apiClient.get<{ runs: ResealRunSummary[] }>(
        "/reseal/runs",
        {
          params: scheduleId
            ? { schedule: scheduleId, limit: RUNS_LIMIT }
            : { limit: RUNS_LIMIT },
        },
      );
      return data.runs;
    },
    refetchInterval: RESEAL_REFRESH_MS,
    staleTime: 5_000,
  });
}

/** Whether a run may still change. */
export function runActive(run: Pick<ResealRunSummary, "status">): boolean {
  return run.status === "queued" || run.status === "running";
}

/**
 * A run with what it did in each repository the viewer can read. It
 * refreshes only while the run is active; a finished run never changes.
 */
export function resealRunQueryOptions(id: string) {
  return queryOptions({
    queryKey: [...RESEAL_KEY, "run", id],
    queryFn: async () => {
      const { data } = await apiClient.get<ResealRun>(
        `/reseal/runs/${encodeURIComponent(id)}`,
      );
      return data;
    },
    refetchInterval: (query) =>
      query.state.data && !runActive(query.state.data)
        ? false
        : RESEAL_REFRESH_MS,
    staleTime: 5_000,
  });
}

/** Which reseal pull requests to list. */
export type PullRequestFilter = ResealPullRequestState | "all";

export function resealPullRequestsQueryOptions(state: PullRequestFilter) {
  return queryOptions({
    queryKey: [...RESEAL_KEY, "pull-requests", state],
    queryFn: async () => {
      const { data } = await apiClient.get<ResealPullRequestList>(
        "/reseal/pull-requests",
        { params: { state } },
      );
      return data;
    },
    refetchInterval: PULL_REQUESTS_REFRESH_MS,
    staleTime: 30_000,
  });
}

/**
 * Creates a schedule. Its first run is `interval_days` from now. The
 * control plane refuses (400, 409) with a sentence saying why.
 */
export async function createSchedule(
  input: ResealScheduleInput,
): Promise<ResealSchedule> {
  const { data } = await apiClient.post<ResealSchedule>(
    "/reseal/schedules",
    input,
  );
  return data;
}

/** Changes any part of a schedule; pausing and resuming are `enabled`. */
export async function updateSchedule(
  id: string,
  patch: Partial<ResealScheduleInput>,
): Promise<ResealSchedule> {
  const { data } = await apiClient.patch<ResealSchedule>(
    schedulePath(id),
    patch,
  );
  return data;
}

/** Deletes a schedule, cancelling its active run. */
export async function deleteSchedule(id: string): Promise<void> {
  await apiClient.delete(schedulePath(id));
}

/** Starts a run of a schedule now; 409 while one is active. */
export async function runSchedule(id: string): Promise<ResealRunSummary> {
  const { data } = await apiClient.post<ResealRunSummary>(
    `${schedulePath(id)}/run`,
  );
  return data;
}

/**
 * Cancels a run: it queues nothing more, its commands in flight expire,
 * and the pull requests it opened stay.
 */
export async function cancelRun(id: string): Promise<ResealRunSummary> {
  const { data } = await apiClient.post<ResealRunSummary>(
    `/reseal/runs/${encodeURIComponent(id)}/cancel`,
  );
  return data;
}
