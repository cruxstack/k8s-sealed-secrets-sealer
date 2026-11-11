import type { FleetAgent, KeyReferences } from "@/api/types";
import { timeAgo } from "@/lib/utils";

/** The capability that lets an agent count key references. */
export const CLEANUP = "cleanup";

/** A count of something, in words: "1 value", "12 values". */
export function plural(n: number, one: string, many = `${one}s`): string {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/**
 * Whether an agent counts key references: `cleanup` is in the registry and
 * in what the agent reports, as the control plane requires.
 */
export function countsReferences(agent: FleetAgent): boolean {
  return (
    (agent.registered_capabilities ?? []).includes(CLEANUP) &&
    (agent.capabilities ?? []).includes(CLEANUP)
  );
}

/**
 * Whether no in-scope agent counts references, so no key's references are
 * known: the fleet says once why, rather than in every row.
 */
export function noneCount(agents: FleetAgent[]): boolean {
  const inScope = agents.filter((a) => a.in_scope);
  return (
    inScope.length > 0 &&
    !inScope.some((a) => countsReferences(a) || a.key_usage !== undefined)
  );
}

const HOUR_MS = 3_600_000;

/**
 * Why an agent's cluster did not count, in a few words: the reasons the
 * control plane leaves a cluster out (no capability, never counted, a
 * failed count, a count older than an hour), as far as the fleet tells.
 */
export function uncountedReason(
  agent: FleetAgent | undefined,
  now: Date,
): string {
  if (!agent) return "not counted";
  const registered = (agent.registered_capabilities ?? []).includes(CLEANUP);
  const reported = (agent.capabilities ?? []).includes(CLEANUP);
  // a capability must be in the Helm values and the registry; say which
  // one lacks it, since that is what to change
  if (!registered && !reported) return "no cleanup capability";
  if (!registered) return "cleanup is not in the agent registry";
  if (!reported) return "the agent does not report cleanup";
  const usage = agent.key_usage;
  if (!usage) return "not counted yet";
  if (usage.error) return `the count failed: ${usage.error}`;
  if (now.getTime() - new Date(usage.counted_at).getTime() > HOUR_MS) {
    return `last counted ${timeAgo(usage.counted_at, now)}`;
  }
  return "not counted";
}

/** What is known of a key's references, for its cell in the key table. */
export type ReferenceSummary =
  /** No cluster counted: the count is unknown. */
  | { kind: "unknown"; uncounted: string[] }
  /** Every cluster counted, and none found a value sealed with it. */
  | { kind: "none" }
  /** Every cluster counted, and found these. */
  | { kind: "known"; values: number; sealedSecrets: number }
  /** Some clusters did not count: there may be more than these. */
  | { kind: "atLeast"; values: number; uncounted: string[] };

/**
 * Sums up a key's references. A 0 is only "none" when every cluster
 * counted; with a cluster left out it is unknown, and any other count is a
 * lower bound.
 */
export function referenceSummary(refs: KeyReferences): ReferenceSummary {
  const counted = refs.clusters ?? [];
  const uncounted = refs.uncounted ?? [];
  if (counted.length === 0) return { kind: "unknown", uncounted };
  if (uncounted.length > 0) {
    return refs.values === 0
      ? { kind: "unknown", uncounted }
      : { kind: "atLeast", values: refs.values, uncounted };
  }
  if (refs.values === 0) return { kind: "none" };
  return {
    kind: "known",
    values: refs.values,
    sealedSecrets: refs.sealed_secrets,
  };
}

/** When the oldest of a key's counts was taken; undefined without counts. */
export function oldestCount(refs: KeyReferences): string | undefined {
  let oldest: string | undefined;
  for (const c of refs.clusters ?? []) {
    if (!oldest || new Date(c.counted_at) < new Date(oldest)) {
      oldest = c.counted_at;
    }
  }
  return oldest;
}
