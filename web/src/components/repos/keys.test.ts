import { describe, expect, it } from "vitest";
import type {
  PendingChange,
  RepositoryFile,
  SealedSecretDocument,
} from "@/api/types";
import {
  NO_PENDING,
  fileRegions,
  keyStatuses,
  missingKeys,
  pendingDocs,
  type PendingDocs,
} from "./keys";

function doc(
  namespace: string,
  keys: string[],
  expected_keys?: string[],
  region?: string,
): SealedSecretDocument {
  return {
    index: 0,
    name: "billing",
    namespace,
    region,
    scope: "strict",
    keys,
    expected_keys,
  };
}

function file(...documents: SealedSecretDocument[]): RepositoryFile {
  return {
    path: "deploy/sealed-secret.yaml",
    blob: "b",
    documents: documents.map((d, index) => ({ ...d, index })),
  };
}

/**
 * Pending values in a file: each key with the namespaces of the documents
 * it waits in.
 */
function pending(
  f: RepositoryFile,
  byKey: Record<string, string[]>,
): PendingDocs {
  const changes: PendingChange[] = Object.entries(byKey).map(
    ([key, namespaces]) => ({
      id: key,
      path: f.path,
      key,
      targets: (f.documents ?? [])
        .filter((d) => namespaces.includes(d.namespace))
        .map((d) => ({
          index: d.index,
          namespace: d.namespace,
          name: d.name,
          scope: "strict",
          region: d.region,
        })),
      sealed_at: "",
      sealed_by: { id: "a" },
      fingerprint: "",
    }),
  );
  return pendingDocs(changes, f.path);
}

describe("keyStatuses", () => {
  it("says where each key stands across the documents", () => {
    const f = file(
      doc("blue", ["token", "url"], ["token", "password"]),
      doc("green", ["url"], ["token", "password"]),
    );
    expect(
      keyStatuses(f, NO_PENDING).map((k) => [k.key, k.state, k.lacking]),
    ).toEqual([
      ["token", "partial", ["green/billing"]],
      ["password", "missing", ["blue/billing", "green/billing"]],
      // url isn't among either document's hints, so neither misses it
      ["url", "set", []],
    ]);
  });

  it("misses a key in a document without hints", () => {
    const f = file(doc("blue", ["url"]), doc("green", []));
    expect(keyStatuses(f, NO_PENDING)[0]).toMatchObject({
      key: "url",
      state: "partial",
      lacking: ["green/billing"],
    });
  });

  it("puts expected keys first, in their order, then the rest by name", () => {
    const f = file(doc("blue", ["b", "a", "z"], ["z", "y"]));
    expect(keyStatuses(f, NO_PENDING).map((k) => k.key)).toEqual([
      "z",
      "y",
      "a",
      "b",
    ]);
  });

  it("counts a pending value only in the documents it was sealed for", () => {
    const f = file(
      doc("blue", ["url"], ["token", "url"], "use1"),
      doc("green", [], ["token", "url"], "use2"),
    );
    const states = keyStatuses(
      f,
      pending(f, { token: ["blue", "green"], url: ["green"], extra: ["blue"] }),
    ).map((k) => [k.key, k.state, k.pending]);
    expect(states).toEqual([
      ["token", "new", 2],
      ["url", "replaced", 1],
      // extra is only for blue; green's hints don't name it
      ["extra", "new", 1],
    ]);
    // a value pending for one region leaves the other lacking
    expect(keyStatuses(f, pending(f, { token: ["blue"] }))[0]).toMatchObject({
      state: "partial",
      pending: 1,
      lacking: ["green/billing in use2"],
    });
  });

  it("says per region where a key stands, when there are regions to tell apart", () => {
    const f = file(
      doc("use1-blue", ["token"], [], "use1"),
      doc("use1-green", [], [], "use1"),
      doc("use2-blue", [], [], "use2"),
      doc("use3-blue", ["token"], ["url"], "use3"),
    );
    expect(
      keyStatuses(f, pending(f, { token: ["use2-blue"] })).find(
        (k) => k.key === "token",
      )?.regions,
    ).toEqual([
      { region: "use1", state: "partial", docs: 2 },
      { region: "use2", state: "pending", docs: 1 },
      { region: "use3", state: "set", docs: 1 },
    ]);
    expect(
      keyStatuses(f, NO_PENDING).find((k) => k.key === "url")?.regions,
    ).toEqual([
      { region: "use1", state: "missing", docs: 2 },
      { region: "use2", state: "missing", docs: 1 },
      { region: "use3", state: "missing", docs: 1 },
    ]);
    // a region whose hints leave the key out doesn't miss it
    const regional = file(
      doc("use1-blue", [], ["endpoint"], "use1"),
      doc("use2-blue", [], ["other"], "use2"),
    );
    expect(keyStatuses(regional, NO_PENDING)[0]).toMatchObject({
      key: "endpoint",
      state: "missing",
      regions: [
        { region: "use1", state: "missing", docs: 1 },
        { region: "use2", state: "unneeded", docs: 1 },
      ],
    });
    // one region: nothing to tell apart
    expect(
      keyStatuses(file(doc("a", ["k"], [], "use1")), NO_PENDING)[0]?.regions,
    ).toEqual([]);
  });

  it("has nothing to show for a file without documents", () => {
    expect(keyStatuses(file(), NO_PENDING)).toEqual([]);
  });
});

describe("fileRegions", () => {
  it("lists the regions in file order, with documents without one as ''", () => {
    expect(
      fileRegions(
        file(doc("a", [], [], "use2"), doc("b", []), doc("c", [], [], "use1")),
      ),
    ).toEqual(["use2", "", "use1"]);
    // one region and documents without one: nothing to choose between
    expect(fileRegions(file(doc("a", [], [], "use1"), doc("b", [])))).toEqual(
      [],
    );
  });
});

describe("missingKeys", () => {
  it("lists the expected keys some document lacks, counting pending ones as there", () => {
    const f = file(
      doc("blue", ["a"], ["a", "b", "c"]),
      doc("green", ["a", "b"], ["a", "b"]),
    );
    expect(missingKeys(f, NO_PENDING)).toEqual(["b", "c"]);
    expect(missingKeys(f, pending(f, { c: ["blue"] }))).toEqual(["b"]);
    expect(missingKeys(f, pending(f, { b: ["blue"], c: ["blue"] }))).toEqual(
      [],
    );
    // pending in another document doesn't count
    expect(missingKeys(f, pending(f, { b: ["green"], c: ["blue"] }))).toEqual([
      "b",
    ]);
  });
});

describe("pendingDocs", () => {
  it("gathers a file's pending documents per key, across changes", () => {
    const change = (
      key: string,
      namespaces: string[],
      path = "deploy/sealed-secret.yaml",
    ): PendingChange => ({
      id: key + namespaces.join(),
      path,
      key,
      targets: namespaces.map((namespace) => ({
        namespace,
        name: "billing",
        scope: "strict",
      })),
      sealed_at: "",
      sealed_by: { id: "a" },
      fingerprint: "",
    });
    const docs = pendingDocs(
      [
        change("token", ["use1"]),
        change("token", ["use2"]),
        change("token", ["use9"], "other.yaml"),
      ],
      "deploy/sealed-secret.yaml",
    );
    expect([...(docs.get("token") ?? [])]).toEqual([
      "/use1/billing",
      "/use2/billing",
    ]);
  });
});

describe("documents with the same namespace and name in each region", () => {
  const f = file(
    doc("apps", [], ["token"], "use1"),
    doc("apps", [], ["token"], "use2"),
  );

  it("are told apart by their place in the file", () => {
    const k = keyStatuses(f, pending(f, {}))[0];
    expect(k?.lacking).toEqual([
      "apps/billing in use1",
      "apps/billing in use2",
    ]);
    const use1: PendingChange = {
      id: "t",
      path: f.path,
      key: "token",
      regions: ["use1"],
      targets: [
        {
          index: 0,
          namespace: "apps",
          name: "billing",
          scope: "strict",
          region: "use1",
        },
      ],
      sealed_at: "",
      sealed_by: { id: "a" },
      fingerprint: "",
    };
    expect(keyStatuses(f, pendingDocs([use1], f.path))[0]).toMatchObject({
      state: "partial",
      pending: 1,
      lacking: ["apps/billing in use2"],
    });
  });

  it("are told apart by region in changes stored without positions", () => {
    const use2: PendingChange = {
      id: "t",
      path: f.path,
      key: "token",
      regions: ["use2"],
      targets: [
        { namespace: "apps", name: "billing", scope: "strict", region: "use2" },
      ],
      sealed_at: "",
      sealed_by: { id: "a" },
      fingerprint: "",
    };
    expect(keyStatuses(f, pendingDocs([use2], f.path))[0]).toMatchObject({
      pending: 1,
      lacking: ["apps/billing in use1"],
    });
  });
});
