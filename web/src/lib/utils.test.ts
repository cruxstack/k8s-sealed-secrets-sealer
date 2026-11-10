import { describe, it, expect } from "vitest";
import { safeReturnPath, shortFingerprint, timeAgo } from "./utils";

describe("safeReturnPath", () => {
  it("keeps same-origin paths", () => {
    expect(safeReturnPath("/")).toBe("/");
    expect(safeReturnPath("/fleet?tab=agents")).toBe("/fleet?tab=agents");
  });

  it("refuses anything that could leave the site or loop", () => {
    for (const bad of [
      "https://evil.example.com",
      "//evil.example.com",
      "/\\evil.example.com",
      "javascript:alert(1)",
      "fleet",
      "/login?error=x",
      "",
      undefined,
      42,
    ]) {
      expect(safeReturnPath(bad)).toBe("/");
    }
  });
});

describe("shortFingerprint", () => {
  it("keeps the algorithm and the start of the digest", () => {
    expect(shortFingerprint("SHA256:abcdefghijklmnopqrstuvwxyz")).toBe(
      "SHA256:abcdefghijkl…",
    );
  });

  it("leaves short values alone", () => {
    expect(shortFingerprint("SHA256:abc")).toBe("SHA256:abc");
  });
});

describe("timeAgo", () => {
  const now = new Date("2026-11-09T12:00:00Z");
  it("formats seconds, minutes, hours and days", () => {
    expect(timeAgo("2026-11-09T11:59:48Z", now)).toBe("12s ago");
    expect(timeAgo("2026-11-09T11:57:00Z", now)).toBe("3m ago");
    expect(timeAgo("2026-11-09T09:00:00Z", now)).toBe("3h ago");
    expect(timeAgo("2026-11-01T12:00:00Z", now)).toBe("8d ago");
    expect(timeAgo("not a date", now)).toBe("unknown");
  });
});
