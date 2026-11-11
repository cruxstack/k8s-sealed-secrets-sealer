import { describe, it, expect } from "vitest";
import {
  CLEANUP_CAPABILITIES,
  agent,
  counted,
  iso,
  keyUsage,
  references,
} from "@/test/fake-api";
import {
  countsReferences,
  noneCount,
  oldestCount,
  plural,
  referenceSummary,
  uncountedReason,
} from "./references";

const counting = (id: string, overrides = {}) =>
  agent({
    id,
    registered_capabilities: CLEANUP_CAPABILITIES,
    capabilities: CLEANUP_CAPABILITIES,
    ...overrides,
  });

describe("plural", () => {
  it("counts in words", () => {
    expect(plural(1, "value")).toBe("1 value");
    expect(plural(0, "value")).toBe("0 values");
    expect(plural(3, "escrowed copy", "escrowed copies")).toBe(
      "3 escrowed copies",
    );
  });
});

describe("referenceSummary", () => {
  it.each([
    {
      name: "every cluster counted none",
      refs: references([counted("use1-blue", 0), counted("use2-blue", 0)]),
      want: { kind: "none" },
    },
    {
      name: "every cluster counted, some values",
      refs: references([
        counted("use1-blue", 8, 3),
        counted("use2-blue", 4, 1),
      ]),
      want: { kind: "known", values: 12, sealedSecrets: 4 },
    },
    {
      // a 0 with a cluster left out is not "none"
      name: "a cluster did not count, the others counted none",
      refs: references([counted("use1-blue", 0)], ["use2-blue"]),
      want: { kind: "unknown", uncounted: ["use2-blue"] },
    },
    {
      name: "a cluster did not count, the others counted some",
      refs: references([counted("use1-blue", 8, 3)], ["use2-blue"]),
      want: { kind: "atLeast", values: 8, uncounted: ["use2-blue"] },
    },
    {
      name: "no cluster counted",
      refs: references([], ["use1-blue", "use2-blue"]),
      want: { kind: "unknown", uncounted: ["use1-blue", "use2-blue"] },
    },
    {
      name: "no cluster in scope",
      refs: references([]),
      want: { kind: "unknown", uncounted: [] },
    },
    {
      // Go sends empty lists as null
      name: "null lists",
      refs: { values: 0, sealed_secrets: 0, clusters: null, uncounted: null },
      want: { kind: "unknown", uncounted: [] },
    },
  ])("$name", ({ refs, want }) => {
    expect(referenceSummary(refs)).toEqual(want);
  });
});

describe("oldestCount", () => {
  it("is the earliest count, or none without counts", () => {
    const old = counted("use2-blue", 0, 0, 20 * 60_000);
    expect(oldestCount(references([counted("use1-blue", 0), old]))).toBe(
      old.counted_at,
    );
    expect(oldestCount(references([], ["use1-blue"]))).toBeUndefined();
  });
});

describe("countsReferences", () => {
  it("needs cleanup in the registry and in what the agent reports", () => {
    expect(countsReferences(counting("a"))).toBe(true);
    expect(countsReferences(agent({ id: "a" }))).toBe(false);
    expect(
      countsReferences(counting("a", { capabilities: ["seal", "keys"] })),
    ).toBe(false);
    expect(
      countsReferences(
        counting("a", { registered_capabilities: ["seal", "keys"] }),
      ),
    ).toBe(false);
  });
});

describe("noneCount", () => {
  it("is set only when no in-scope agent counts or has counted", () => {
    expect(noneCount([agent({ id: "a" }), agent({ id: "b" })])).toBe(true);
    expect(noneCount([agent({ id: "a" }), counting("b")])).toBe(false);
    // a count stays meaningful after the capability is taken away
    expect(noneCount([agent({ id: "a", key_usage: keyUsage() })])).toBe(false);
    // an agent out of scope does not count either way
    expect(
      noneCount([agent({ id: "a" }), counting("b", { in_scope: false })]),
    ).toBe(true);
    // with no agent in scope there is nothing to explain
    expect(noneCount([counting("a", { in_scope: false })])).toBe(false);
    expect(noneCount([])).toBe(false);
  });
});

describe("uncountedReason", () => {
  const now = new Date();
  it.each([
    { name: "unknown agent", a: undefined, want: "not counted" },
    {
      name: "no capability",
      a: agent({ id: "a" }),
      want: "no cleanup capability",
    },
    {
      name: "only in the Helm values",
      a: counting("a", { registered_capabilities: ["seal", "keys"] }),
      want: "cleanup is not in the agent registry",
    },
    {
      name: "only in the registry",
      a: counting("a", { capabilities: ["seal", "keys"] }),
      want: "the agent does not report cleanup",
    },
    { name: "never counted", a: counting("a"), want: "not counted yet" },
    {
      name: "failed",
      a: counting("a", {
        key_usage: keyUsage({ error: "cannot list sealedsecrets: forbidden" }),
      }),
      want: "the count failed: cannot list sealedsecrets: forbidden",
    },
    {
      name: "stale",
      a: counting("a", {
        key_usage: keyUsage({ counted_at: iso(2 * 3_600_000) }),
      }),
      want: "last counted 2h ago",
    },
  ])("$name", ({ a, want }) => {
    expect(uncountedReason(a, now)).toBe(want);
  });
});
