import { describe, it, expect } from "vitest";
import {
  relativeTime,
  safeReturnPath,
  sentence,
  shortFingerprint,
  timeAgo,
} from "./utils";

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

  it("says just now rather than 0s ago, even a little ahead of this clock", () => {
    expect(timeAgo("2026-11-09T12:00:00Z", now)).toBe("just now");
    expect(timeAgo("2026-11-09T11:59:57Z", now)).toBe("just now");
    expect(timeAgo("2026-11-09T12:00:30Z", now)).toBe("just now");
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-11-09T12:00:00Z");
  it("reads the past and the future", () => {
    expect(relativeTime("2026-11-09T11:00:00Z", now)).toBe("1h ago");
    expect(relativeTime("2026-11-09T12:40:00Z", now)).toBe("in 40m");
    expect(relativeTime("2026-11-12T12:00:00Z", now)).toBe("in 3d");
    expect(relativeTime("2026-11-09T12:00:02Z", now)).toBe("just now");
  });
});

describe("sentence", () => {
  it("capitalizes server text and ends it with a full stop", () => {
    expect(sentence("cluster-wide scope is not allowed")).toBe(
      "Cluster-wide scope is not allowed.",
    );
    expect(sentence("file is not valid YAML")).toBe("File is not valid YAML.");
    expect(sentence("Sealing works.")).toBe("Sealing works.");
  });

  it("keeps identifiers as they are", () => {
    expect(sentence("metadata.name is missing")).toBe(
      "metadata.name is missing.",
    );
    expect(sentence("deploy/billing.yaml: seal it again")).toBe(
      "deploy/billing.yaml: seal it again.",
    );
  });
});
