import { describe, it, expect, vi } from "vitest";
import type { Repository } from "@/api/types";
import { MAX_RECENT, recentItems, rememberSeal } from "./recent-repos";

const KEY = "sealer.recent-repos:octocat:dev";

function stored(key = KEY) {
  return JSON.parse(localStorage.getItem(key) ?? "[]") as unknown[];
}

function repo(full_name: string): Repository {
  const [owner = "", name = ""] = full_name.split("/");
  return {
    owner,
    name,
    full_name,
    private: true,
    default_branch: "main",
    access: "write",
  };
}

describe("rememberSeal", () => {
  it("keeps the latest seal per repository first, per user and env", () => {
    rememberSeal("octocat", "dev", "example-org/apps", "a.yaml", new Date(1));
    rememberSeal("octocat", "dev", "example-org/web", "b.yaml", new Date(2));
    // the same repository, spelled otherwise, moves to the top
    rememberSeal("octocat", "dev", "Example-Org/Apps", "c.yaml", new Date(3));
    expect(stored()).toEqual([
      {
        repository: "Example-Org/Apps",
        path: "c.yaml",
        sealed_at: new Date(3).toISOString(),
      },
      {
        repository: "example-org/web",
        path: "b.yaml",
        sealed_at: new Date(2).toISOString(),
      },
    ]);
    // another env and another user have their own
    expect(stored("sealer.recent-repos:octocat:prod")).toEqual([]);
    expect(stored("sealer.recent-repos:hubot:dev")).toEqual([]);
  });

  it("remembers a limited number", () => {
    for (let i = 0; i < MAX_RECENT + 3; i++) {
      rememberSeal("octocat", "dev", `example-org/r${i}`, "s.yaml");
    }
    const list = stored() as { repository: string }[];
    expect(list).toHaveLength(MAX_RECENT);
    expect(list[0]?.repository).toBe(`example-org/r${MAX_RECENT + 2}`);
  });

  it("starts afresh from what it cannot read, and survives storage it may not use", () => {
    localStorage.setItem(KEY, "{not json");
    rememberSeal("octocat", "dev", "example-org/apps", "a.yaml");
    expect(stored()).toHaveLength(1);
    localStorage.setItem(
      KEY,
      JSON.stringify([{ repository: 1 }, { repository: "x/y", sealed_at: "" }]),
    );
    rememberSeal("octocat", "dev", "example-org/apps", "a.yaml");
    expect(stored()).toHaveLength(1);

    const set = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new Error("QuotaExceededError");
      });
    expect(() =>
      rememberSeal("octocat", "dev", "example-org/web", "b.yaml"),
    ).not.toThrow();
    set.mockRestore();
  });

  it("remembers nothing without a user or env", () => {
    rememberSeal("", "dev", "example-org/apps", "a.yaml");
    rememberSeal("octocat", "", "example-org/apps", "a.yaml");
    expect(localStorage.length).toBe(0);
  });
});

describe("recentItems", () => {
  const repos = ["example-org/apps", "example-org/web", "example-org/api"].map(
    repo,
  );
  const at = (ms: number) => new Date(ms).toISOString();

  it("puts pending changes first, then the latest seals, in the list only", () => {
    const items = recentItems(
      repos,
      new Map([
        ["example-org/api", 2],
        ["example-org/none", 0],
      ]),
      [
        { repository: "example-org/web", path: "w.yaml", sealed_at: at(3) },
        // gone from the list: the user can no longer read it
        { repository: "example-org/gone", path: "g.yaml", sealed_at: at(2) },
        { repository: "Example-Org/Apps", path: "a.yaml", sealed_at: at(1) },
      ],
    );
    expect(
      items.map((i) => [i.repo.full_name, i.pending, i.path ?? null]),
    ).toEqual([
      ["example-org/api", 2, null],
      ["example-org/web", 0, "w.yaml"],
      ["example-org/apps", 0, "a.yaml"],
    ]);
  });

  it("shows at most six", () => {
    const many = Array.from({ length: 9 }, (_, i) => repo(`o/r${i}`));
    const items = recentItems(
      many,
      new Map(),
      many.map((r, i) => ({
        repository: r.full_name,
        sealed_at: at(100 - i),
      })),
    );
    expect(items.map((i) => i.repo.full_name)).toEqual([
      "o/r0",
      "o/r1",
      "o/r2",
      "o/r3",
      "o/r4",
      "o/r5",
    ]);
  });
});
