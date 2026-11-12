import { describe, it, expect, vi } from "vitest";
import type { Repository } from "@/api/types";
import {
  REPO_CACHE_MAX_AGE_MS,
  clearRepoCache,
  forgetBrowserData,
  readRepoCache,
  writeRepoCache,
} from "./repo-cache";
import { rememberSeal } from "./recent-repos";

const DEV = { user: 7, env: "dev" };
const KEY = "sealer.repos.v1:7:dev";
const NOW = Date.parse("2026-11-12T12:00:00Z");

const APPS: Repository = {
  owner: "example-org",
  name: "apps",
  full_name: "example-org/apps",
  private: true,
  default_branch: "main",
  access: "write",
};

describe("the saved repository list", () => {
  it("keeps the server's list per user and env, with when it came", () => {
    writeRepoCache(DEV, { repositories: [APPS], incomplete: true }, NOW);
    expect(readRepoCache(DEV, NOW + 1000)).toEqual({
      list: { repositories: [APPS], incomplete: true },
      at: NOW,
    });
    // another env, and another user (by id, which a renamed login keeps)
    expect(readRepoCache({ user: 7, env: "prod" }, NOW)).toBeNull();
    expect(readRepoCache({ user: 8, env: "dev" }, NOW)).toBeNull();
  });

  it("saves only what the list shows", () => {
    writeRepoCache(
      DEV,
      {
        repositories: [
          { ...APPS, permissions: { admin: true }, token: "x" } as Repository,
        ],
      },
      NOW,
    );
    const stored = localStorage.getItem(KEY) ?? "";
    expect(stored).not.toContain("permissions");
    expect(stored).not.toContain("token");
    expect(readRepoCache(DEV, NOW)?.list.repositories).toEqual([APPS]);
  });

  it("drops a list that is too old, from the future, or of another version", () => {
    writeRepoCache(DEV, { repositories: [APPS] }, NOW);
    expect(readRepoCache(DEV, NOW + REPO_CACHE_MAX_AGE_MS)).not.toBeNull();
    expect(readRepoCache(DEV, NOW + REPO_CACHE_MAX_AGE_MS + 1)).toBeNull();
    // a clock that moved back a little is fine; much further is not
    expect(readRepoCache(DEV, NOW - 60_000)).not.toBeNull();
    expect(readRepoCache(DEV, NOW - 3_600_000)).toBeNull();
    const entry = JSON.parse(localStorage.getItem(KEY) ?? "");
    localStorage.setItem(KEY, JSON.stringify({ ...entry, v: 2 }));
    expect(readRepoCache(DEV, NOW)).toBeNull();
  });

  it("refuses a list it cannot trust", () => {
    const save = (list: unknown) =>
      localStorage.setItem(KEY, JSON.stringify({ v: 1, at: NOW, list }));
    for (const list of [
      null,
      { repositories: "x" },
      { repositories: [{ ...APPS, access: "admin" }] },
      { repositories: [{ ...APPS, full_name: "other-org/apps" }] },
      { repositories: [{ ...APPS, private: "yes" }] },
      { repositories: [APPS, 1] },
    ]) {
      save(list);
      expect(readRepoCache(DEV, NOW)).toBeNull();
    }
    localStorage.setItem(KEY, "{not json");
    expect(readRepoCache(DEV, NOW)).toBeNull();
  });

  it("works without storage it may use", () => {
    const get = vi
      .spyOn(Storage.prototype, "getItem")
      .mockImplementation(() => {
        throw new Error("SecurityError");
      });
    const set = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new Error("QuotaExceededError");
      });
    expect(() =>
      writeRepoCache(DEV, { repositories: [APPS] }, NOW),
    ).not.toThrow();
    expect(readRepoCache(DEV, NOW)).toBeNull();
    get.mockRestore();
    set.mockRestore();
  });

  it("drops one list, or every user's lists and recent repositories on sign-out", () => {
    writeRepoCache(DEV, { repositories: [APPS] }, NOW);
    clearRepoCache(DEV);
    expect(localStorage.getItem(KEY)).toBeNull();

    writeRepoCache(DEV, { repositories: [APPS] }, NOW);
    writeRepoCache({ user: 8, env: "prod" }, { repositories: [APPS] }, NOW);
    rememberSeal("octocat", "dev", "example-org/apps", "a.yaml");
    localStorage.setItem("sealer-theme", "dark");
    forgetBrowserData();
    expect(Object.keys(localStorage)).toEqual(["sealer-theme"]);
  });
});
