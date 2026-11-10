import { describe, expect, it } from "vitest";
import type { RepositoryFile, SealedSecretDocument } from "@/api/types";
import { keyStatuses } from "./keys";

function doc(
  namespace: string,
  keys: string[],
  expected_keys?: string[],
): SealedSecretDocument {
  return {
    index: 0,
    name: "billing",
    namespace,
    scope: "strict",
    keys,
    expected_keys,
  };
}

function file(...documents: SealedSecretDocument[]): RepositoryFile {
  return { path: "deploy/sealed-secret.yaml", blob: "b", documents };
}

const NONE = new Set<string>();

describe("keyStatuses", () => {
  it("says where each key stands across the documents", () => {
    const f = file(
      doc("blue", ["token", "url"], ["token", "password"]),
      doc("green", ["url"], ["token", "password"]),
    );
    expect(keyStatuses(f, NONE)).toEqual([
      {
        key: "token",
        state: "partial",
        expected: true,
        holders: 1,
        lacking: ["green/billing"],
      },
      {
        key: "password",
        state: "missing",
        expected: true,
        holders: 0,
        lacking: ["blue/billing", "green/billing"],
      },
      {
        key: "url",
        state: "set",
        expected: false,
        holders: 2,
        lacking: [],
      },
    ]);
  });

  it("puts expected keys first, in their order, then the rest by name", () => {
    const f = file(doc("blue", ["b", "a", "z"], ["z", "y"]));
    expect(keyStatuses(f, NONE).map((k) => k.key)).toEqual([
      "z",
      "y",
      "a",
      "b",
    ]);
  });

  it("settles a key with a pending value, new or replacing", () => {
    const f = file(doc("blue", ["url"], ["token"]), doc("green", []));
    const states = keyStatuses(f, new Set(["token", "url", "extra"])).map(
      (k) => [k.key, k.state],
    );
    expect(states).toEqual([
      ["token", "new"],
      ["extra", "new"],
      ["url", "replaced"],
    ]);
  });

  it("has nothing to show for a file without documents", () => {
    expect(keyStatuses(file(), NONE)).toEqual([]);
  });
});
