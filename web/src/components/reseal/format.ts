import type { ResealScheduleInput, SealingStatus } from "@/api/types";
import { extractApiError } from "@/api/client";
import { sentence } from "@/lib/utils";

const DAY_MS = 86_400_000;
/** The average month, so 75 days reads as 2½ months. */
const MONTH_DAYS = 365.25 / 12;

/** The limits the control plane checks a schedule against. */
export const LIMITS = {
  name: 100,
  repos: 100,
  orgs: 20,
  minDays: 1,
  maxDays: 365,
  schedules: 50,
} as const;

/** "2", "2½": n rounded to the nearest half. */
function halves(n: number): string {
  const rounded = Math.round(n * 2) / 2;
  const whole = Math.floor(rounded);
  return rounded === whole ? `${whole}` : `${whole || ""}½`;
}

/** "1 week", "2½ weeks". */
function about(n: number, unit: string): string {
  const amount = halves(n);
  return `${amount} ${amount === "1" ? unit : `${unit}s`}`;
}

/**
 * An interval in days in weeks, months or a year, as people think of it:
 * "≈ 2½ months" for 75, "= 2 weeks" for 14, "= 1 year" for 365. Short
 * intervals need none and get null, as does a value that is not a whole
 * number of days in range.
 */
export function intervalApprox(days: number): string | null {
  if (!Number.isInteger(days) || days < 7 || days > LIMITS.maxDays) {
    return null;
  }
  if (days === 365) return "= 1 year";
  if (days < 28) {
    return `${days % 7 === 0 ? "=" : "≈"} ${about(days / 7, "week")}`;
  }
  const months = days / MONTH_DAYS;
  if (Math.round(months * 2) / 2 >= 12) return "≈ 1 year";
  return `≈ ${about(months, "month")}`;
}

/** The interval field's hint: "75 days ≈ 2½ months". */
export function intervalHint(days: number): string | null {
  const approx = intervalApprox(days);
  return approx && `${days} days ${approx}`;
}

/** How long something took: "42s", "4m 12s", "3h 5m", "2d 4h". */
export function formatDuration(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  if (seconds < 60) return `${seconds}s`;
  // "3m", not "3m 0s"
  const and = (n: number, unit: string) => (n > 0 ? ` ${n}${unit}` : "");
  if (minutes < 60) return `${minutes}m${and(seconds % 60, "s")}`;
  if (hours < 48) return `${hours}h${and(minutes % 60, "m")}`;
  return `${days}d${and(hours % 24, "h")}`;
}

/** Whole days between two times, rounded down. */
export function daysBetween(from: string, to: Date): number {
  return Math.floor((to.getTime() - new Date(from).getTime()) / DAY_MS);
}

/** When a schedule made now, or resumed now, first runs. */
export function firstRunAt(days: number, now: Date): Date {
  return new Date(now.getTime() + days * DAY_MS);
}

/** A date without its time: "Jan 25, 2027". */
export function formatDate(d: Date): string {
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

// GitHub's rules: an owner is letters, digits and single hyphens, up to 39
// characters, not starting with a hyphen; a repository name is letters,
// digits, '.', '_' and '-', up to 100 characters
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_NAME = /^[A-Za-z0-9._-]{1,100}$/;

/** Why a repository is not `owner/name`, or null when it is. */
export function repoProblem(value: string): string | null {
  const parts = value.split("/");
  if (
    parts.length !== 2 ||
    !OWNER.test(parts[0]!) ||
    !REPO_NAME.test(parts[1]!) ||
    parts[1] === "." ||
    parts[1] === ".."
  ) {
    return "Use owner/name, as in example-org/apps.";
  }
  return null;
}

/** Why an org is not a GitHub login, or null when it is. */
export function orgProblem(value: string): string | null {
  return OWNER.test(value)
    ? null
    : "Use the org's login, as in example-org: letters, digits and hyphens.";
}

/** What is wrong with a schedule, per field, as the control plane checks. */
export interface ScheduleProblems {
  name?: string;
  scope?: string;
  interval?: string;
}

/**
 * Checks a schedule as the control plane does, so the form says what is
 * wrong before it is sent. Each repository and org was checked as it was
 * added.
 */
export function scheduleProblems(input: ResealScheduleInput): ScheduleProblems {
  const problems: ScheduleProblems = {};
  const name = input.name.trim();
  if (name === "") problems.name = "Name the schedule.";
  else if (name.length > LIMITS.name) {
    problems.name = `Use at most ${LIMITS.name} characters.`;
  }
  if (input.repos.length === 0 && input.orgs.length === 0) {
    problems.scope = "Add a repository or an org.";
  } else if (input.repos.length > LIMITS.repos) {
    problems.scope = `A schedule takes at most ${LIMITS.repos} repositories.`;
  } else if (input.orgs.length > LIMITS.orgs) {
    problems.scope = `A schedule takes at most ${LIMITS.orgs} orgs.`;
  }
  const days = input.interval_days;
  if (
    !Number.isInteger(days) ||
    days < LIMITS.minDays ||
    days > LIMITS.maxDays
  ) {
    problems.interval = `Use a whole number of days from ${LIMITS.minDays} to ${LIMITS.maxDays}.`;
  }
  return problems;
}

/**
 * Why values cannot be resealed in the env now, as a sentence; undefined
 * when they can, or while that is not known yet.
 */
export function resealBlocked(
  status: SealingStatus | undefined,
): string | undefined {
  if (!status || status.can_reseal) return undefined;
  return sentence(
    status.reseal_blocked ?? "This control plane cannot reseal values.",
  );
}

/**
 * Why nothing can be resealed now, for an action that would: what the
 * status says, that it could not be read (it is read again every 30
 * seconds), or that it is being read. Undefined when values can be
 * resealed.
 */
export function resealReason(
  status: SealingStatus | undefined,
  error: unknown,
): string | undefined {
  if (status) return resealBlocked(status);
  if (error) {
    return `Couldn't check whether values can be resealed: ${sentence(extractApiError(error))} Trying again.`;
  }
  return "Checking whether values can be resealed…";
}

/**
 * A reseal failure's regions: its list, or the one region of a failure
 * kept from before documents could list several.
 */
export function failureRegions(f: {
  regions?: string[];
  region?: string;
}): string[] {
  if (f.regions?.length) return f.regions;
  return f.region ? [f.region] : [];
}
