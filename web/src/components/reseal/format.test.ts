import { describe, it, expect } from "vitest";
import {
  formatDuration,
  intervalApprox,
  intervalHint,
  orgProblem,
  repoProblem,
  scheduleProblems,
} from "./format";
import { resealSearch } from "./search";

describe("intervalHint", () => {
  it.each([
    [1, null],
    [6, null],
    [7, "7 days = 1 week"],
    [10, "10 days ≈ 1½ weeks"],
    [14, "14 days = 2 weeks"],
    [30, "30 days ≈ 1 month"],
    [45, "45 days ≈ 1½ months"],
    [75, "75 days ≈ 2½ months"],
    [90, "90 days ≈ 3 months"],
    [180, "180 days ≈ 6 months"],
    [360, "360 days ≈ 1 year"],
    [365, "365 days = 1 year"],
    [366, null],
    [7.5, null],
    [Number.NaN, null],
  ])("words %s days as %s", (days, hint) => {
    expect(intervalHint(days)).toBe(hint);
  });

  it("gives the table its approximation alone", () => {
    expect(intervalApprox(75)).toBe("≈ 2½ months");
    expect(intervalApprox(3)).toBeNull();
  });
});

describe("formatDuration", () => {
  it.each([
    [0, "0s"],
    [42_000, "42s"],
    [252_000, "4m 12s"],
    [3 * 3_600_000 + 5 * 60_000, "3h 5m"],
    [52 * 3_600_000, "2d 4h"],
    [180_000, "3m"],
    [48 * 3_600_000, "2d"],
    [-5_000, "0s"],
  ])("words %s ms as %s", (ms, text) => {
    expect(formatDuration(ms)).toBe(text);
  });
});

describe("repoProblem and orgProblem", () => {
  it.each([
    "example-org/apps",
    "example-org/apps.v2",
    "a/b_c-d",
    "Example-Org/Apps",
  ])("takes the repository %s", (repo) => {
    expect(repoProblem(repo)).toBeNull();
  });

  it.each([
    "apps",
    "example-org/",
    "/apps",
    "example-org/apps/extra",
    "-org/apps",
    "example org/apps",
    "example-org/..",
    "https://github.com/example-org/apps",
  ])("refuses the repository %s", (repo) => {
    expect(repoProblem(repo)).toBe("Use owner/name, as in example-org/apps.");
  });

  it("takes an org's login and refuses anything else", () => {
    expect(orgProblem("example-org")).toBeNull();
    expect(orgProblem("example-org/apps")).toMatch(/org's login/);
    expect(orgProblem("-org")).toMatch(/org's login/);
    expect(orgProblem("a".repeat(40))).toMatch(/org's login/);
  });
});

describe("scheduleProblems", () => {
  const valid = {
    name: "Platform",
    repos: ["example-org/apps"],
    orgs: [],
    interval_days: 75,
    enabled: true,
  };

  it("finds nothing wrong with a valid schedule", () => {
    expect(scheduleProblems(valid)).toEqual({});
    expect(
      scheduleProblems({ ...valid, repos: [], orgs: ["example-org"] }),
    ).toEqual({});
  });

  it("checks what the control plane checks", () => {
    expect(
      scheduleProblems({
        name: "  ",
        repos: [],
        orgs: [],
        interval_days: 0,
        enabled: true,
      }),
    ).toEqual({
      name: "Name the schedule.",
      scope: "Add a repository or an org.",
      interval: "Use a whole number of days from 1 to 365.",
    });
    expect(scheduleProblems({ ...valid, name: "x".repeat(101) }).name).toBe(
      "Use at most 100 characters.",
    );
    expect(
      scheduleProblems({
        ...valid,
        repos: Array.from({ length: 101 }, (_, i) => `o/r${i}`),
      }).scope,
    ).toBe("A schedule takes at most 100 repositories.");
    expect(
      scheduleProblems({
        ...valid,
        orgs: Array.from({ length: 21 }, (_, i) => `o${i}`),
      }).scope,
    ).toBe("A schedule takes at most 20 orgs.");
    expect(scheduleProblems({ ...valid, interval_days: 366 }).interval).toBe(
      "Use a whole number of days from 1 to 365.",
    );
    expect(
      scheduleProblems({ ...valid, interval_days: 1.5 }).interval,
    ).toBeDefined();
  });
});

describe("resealSearch", () => {
  it("keeps what the page understands", () => {
    expect(
      resealSearch({ prs: "merged", schedule: "s1", run: "r1", other: "x" }),
    ).toEqual({ prs: "merged", schedule: "s1", run: "r1" });
    // open is the default, so it never shows in the URL
    expect(resealSearch({ prs: "open", schedule: "", run: 3 })).toEqual({});
  });
});
