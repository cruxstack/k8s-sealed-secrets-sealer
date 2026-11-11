import { describe, it, expect } from "vitest";
import { ApiError } from "@/api/client";
import type { ResealRun, ResealSchedule } from "@/api/types";
import { resealRun, resealSchedule } from "@/test/fake-api";
import {
  ACTIVE_REFRESH_MS,
  IDLE_REFRESH_MS,
  PULL_REQUESTS_REFRESH_MS,
  pollAfter,
  resealPullRequestsQueryOptions,
  resealRunQueryOptions,
  resealRunsQueryOptions,
  resealSchedulesQueryOptions,
} from "./reseal";

/** A query's state as refetchInterval sees it. */
function query<T>(data: T | undefined, error?: unknown) {
  return {
    state: { data, error: error ?? null, status: error ? "error" : "success" },
  };
}

/** The next poll a query's options ask for, given its state. */
function next(
  options: { refetchInterval?: unknown },
  state: ReturnType<typeof query>,
): number | false {
  const fn = options.refetchInterval as (q: unknown) => number | false;
  return fn(state);
}

const running: ResealRun = {
  ...resealRun({ id: "r", status: "running", finished_at: undefined }),
  repositories: [],
};
const finished: ResealRun = { ...resealRun({ id: "r" }), repositories: [] };

describe("reseal polling", () => {
  it("polls schedules and runs faster only while a run is active", () => {
    const idle: ResealSchedule[] = [resealSchedule({ id: "s" })];
    const busy = [{ ...idle[0]!, active_run_id: "r" }];
    expect(next(resealSchedulesQueryOptions, query(idle))).toBe(
      IDLE_REFRESH_MS,
    );
    expect(next(resealSchedulesQueryOptions, query(busy))).toBe(
      ACTIVE_REFRESH_MS,
    );
    const runs = resealRunsQueryOptions();
    expect(next(runs, query([finished]))).toBe(IDLE_REFRESH_MS);
    expect(next(runs, query([finished, running]))).toBe(ACTIVE_REFRESH_MS);
  });

  it("stops polling a run once it has finished", () => {
    const run = resealRunQueryOptions("r");
    expect(next(run, query(running))).toBe(ACTIVE_REFRESH_MS);
    expect(next(run, query(finished))).toBe(false);
  });

  it("stops after a 401, 403 or 404, which asking again won't change", () => {
    const run = resealRunQueryOptions("r");
    for (const status of [401, 403, 404]) {
      expect(next(run, query(undefined, new ApiError("no", status)))).toBe(
        false,
      );
    }
    expect(
      next(
        resealPullRequestsQueryOptions("open"),
        query(undefined, new ApiError("only admins can see this", 403)),
      ),
    ).toBe(false);
  });

  it("waits as long as a 429 or 503 asks, a minute at least on a 429", () => {
    const run = resealRunQueryOptions("r");
    expect(next(run, query(running, new ApiError("slow down", 429, 30)))).toBe(
      30_000,
    );
    expect(next(run, query(running, new ApiError("slow down", 429)))).toBe(
      60_000,
    );
    expect(next(run, query(running, new ApiError("starting", 503, 5)))).toBe(
      ACTIVE_REFRESH_MS,
    );
    // never sooner than the usual interval
    expect(
      next(
        resealPullRequestsQueryOptions("all"),
        query(undefined, new ApiError("slow down", 429, 1)),
      ),
    ).toBe(PULL_REQUESTS_REFRESH_MS);
  });

  it("keeps polling as usual after other errors, which may pass", () => {
    expect(pollAfter(new ApiError("bad gateway", 502), 10_000)).toBe(10_000);
    expect(pollAfter(new ApiError("unreachable"), 10_000)).toBe(10_000);
    expect(pollAfter(new Error("odd"), 10_000)).toBe(10_000);
  });
});
