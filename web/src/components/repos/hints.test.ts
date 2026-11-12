import { describe, it, expect } from "vitest";
import type { RepositoryFile, SealedSecretDocument } from "@/api/types";
import { fileHints, sortFiles } from "./hints";

function doc(over: Partial<SealedSecretDocument>): SealedSecretDocument {
  return {
    index: 0,
    name: "billing",
    namespace: "apps",
    scope: "strict",
    keys: [],
    ...over,
  };
}

function file(
  documents: SealedSecretDocument[],
  path = "sealed.yaml",
): RepositoryFile {
  return { path, blob: "b", documents };
}

describe("fileHints", () => {
  it("takes the first title, description and docs, and every expected key once", () => {
    const hints = fileHints(
      file([
        doc({ expected_keys: ["b", "a"] }),
        doc({
          title: "Billing API",
          description: "Payment credentials",
          docs: "https://docs.example.com/billing",
          expected_keys: ["a", "c"],
        }),
        doc({
          title: "Other",
          description: "Other",
          docs: "https://other.example.com",
        }),
      ]),
    );
    expect(hints).toEqual({
      title: "Billing API",
      description: "Payment credentials",
      docs: "https://docs.example.com/billing",
      expected: ["b", "a", "c"],
    });
  });

  it("drops a docs link that is not http(s)", () => {
    const hints = fileHints(file([doc({ docs: "javascript:alert(1)" })]));
    expect(hints.docs).toBeUndefined();
  });

  it("has nothing for a file without hints or documents", () => {
    expect(fileHints({ path: "x", blob: "b", documents: null })).toEqual({
      title: undefined,
      description: undefined,
      docs: undefined,
      expected: [],
    });
  });

  it("takes the first order given, 0 included", () => {
    expect(
      fileHints(file([doc({}), doc({ order: 0 }), doc({ order: 3 })])).order,
    ).toBe(0);
    expect(fileHints(file([doc({})])).order).toBeUndefined();
  });
});

describe("sortFiles", () => {
  it("puts files with an order first, lowest first, then the rest as they came", () => {
    const files = [
      file([doc({})], "a.yaml"),
      file([doc({ order: 10 })], "b.yaml"),
      file([], "c.yaml"),
      file([doc({ order: 0 })], "d.yaml"),
      file([doc({})], "e.yaml"),
      file([doc({ order: 10 })], "f.yaml"),
    ];
    expect(sortFiles(files).map((f) => f.path)).toEqual([
      "d.yaml",
      // a tie keeps the order the files came in
      "b.yaml",
      "f.yaml",
      "a.yaml",
      "c.yaml",
      "e.yaml",
    ]);
    // the list it was given stays as it was
    expect(files[0]?.path).toBe("a.yaml");
  });
});
