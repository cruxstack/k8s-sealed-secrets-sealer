import type { PullRequestFilter } from "@/api/queries/reseal";

/** The reseal page's search: what it shows, so a link opens the same. */
export interface ResealSearch {
  /** The reseal pull requests listed; the open ones when absent. */
  prs?: Exclude<PullRequestFilter, "open">;
  /** The schedule whose runs are listed; every schedule's when absent. */
  schedule?: string;
  /** The run whose detail is open. */
  run?: string;
}

const FILTERS = new Set<string>(["merged", "closed", "all"]);

/** Keeps what the reseal page understands of a URL's search. */
export function resealSearch(search: Record<string, unknown>): ResealSearch {
  const out: ResealSearch = {};
  if (typeof search.prs === "string" && FILTERS.has(search.prs)) {
    out.prs = search.prs as ResealSearch["prs"];
  }
  if (typeof search.schedule === "string" && search.schedule !== "") {
    out.schedule = search.schedule;
  }
  if (typeof search.run === "string" && search.run !== "") {
    out.run = search.run;
  }
  return out;
}
