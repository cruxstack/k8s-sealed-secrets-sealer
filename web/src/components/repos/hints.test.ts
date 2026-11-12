import { describe, it, expect } from "vitest";
import type { RepositoryFile, SealedSecretDocument } from "@/api/types";
import { fileHints } from "./hints";

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

function file(documents: SealedSecretDocument[]): RepositoryFile {
  return { path: "sealed.yaml", blob: "b", documents };
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
});
