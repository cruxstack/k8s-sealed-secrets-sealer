import { describe, it, expect } from "vitest";
import { repoFilesQueryOptions, reposQueryOptions } from "./repos";

// Listings cost the control plane GitHub calls, so they are fetched again
// only when they can have changed.
describe("repository queries", () => {
  it("never fetches a listing pinned to a commit again", () => {
    const pinned = repoFilesQueryOptions("example-org", "apps", "abc123");
    expect(pinned.staleTime).toBe(Infinity);
    expect(pinned.refetchOnWindowFocus).toBe(false);
  });

  it("fetches the head's listing again once stale, on focus too", () => {
    const head = repoFilesQueryOptions("example-org", "apps");
    expect(head.staleTime).toBe(30_000);
    expect(head.refetchOnWindowFocus).toBe(true);
  });

  it("does not fetch the repository list again on focus", () => {
    expect(reposQueryOptions.refetchOnWindowFocus).toBe(false);
  });
});
