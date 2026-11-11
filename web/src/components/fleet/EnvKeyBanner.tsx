import { KeyRound, TriangleAlert } from "lucide-react";
import type { Fleet } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { RelativeTime } from "@/components/ui/relative-time";
import { cn, shortFingerprint } from "@/lib/utils";
import { CopyButton } from "./CopyButton";

/** What to expect while no key is held by every cluster. */
function outOfSyncDetail(fleet: Fleet): string {
  const agents = fleet.agents ?? [];
  if (agents.length > 0 && agents.every((a) => !a.checked_in)) {
    return "No agent has checked in yet; sealing starts once the clusters report their keys.";
  }
  if (agents.some((a) => a.in_scope && (a.missing_keys ?? []).length > 0)) {
    return "The Missing column below counts the keys each cluster lacks; key sync restores them on its next check-ins.";
  }
  return "Key sync restores what each cluster lacks on its next check-ins.";
}

/**
 * The env's key state: the env key values are sealed with, or why there is
 * none and sealing is unavailable.
 */
export function EnvKeyBanner({ fleet }: { fleet: Fleet }) {
  const key = fleet.env_key;
  const inSync = fleet.keys_in_sync && key !== null;
  const env = <span className="font-medium text-foreground">{fleet.env}</span>;

  return (
    <Card
      role="region"
      aria-label="Env key"
      className={cn(!inSync && "border-destructive/40")}
    >
      <CardContent
        role={inSync ? undefined : "alert"}
        className="flex flex-col gap-4 p-5 md:flex-row md:items-center md:justify-between"
      >
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg",
              inSync
                ? "bg-success-subtle text-success"
                : "bg-destructive-subtle text-destructive",
            )}
          >
            {inSync ? (
              <KeyRound className="h-5 w-5" aria-hidden="true" />
            ) : (
              <TriangleAlert className="h-5 w-5" aria-hidden="true" />
            )}
          </div>
          <div className="space-y-0.5">
            <h2 className="text-lg font-semibold">
              {inSync
                ? "Keys in sync"
                : fleet.no_usable_key
                  ? "New key needed"
                  : "Keys out of sync"}
            </h2>
            <p className="max-w-2xl text-sm text-muted-foreground">
              {inSync ? (
                <>
                  Values in the {env} env are sealed with the env key, the
                  newest key every cluster holds.
                </>
              ) : fleet.no_usable_key ? (
                <>
                  Every key the clusters share is revoked or not valid yet, so
                  sealing in the {env} env is unavailable. Let a controller
                  renew its key, or reinstate a key revoked by mistake.
                </>
              ) : (
                <>
                  No key is held by every cluster yet, so sealing in the {env}{" "}
                  env is unavailable. {outOfSyncDetail(fleet)}
                </>
              )}
            </p>
          </div>
        </div>

        {inSync && key ? (
          <dl className="grid shrink-0 grid-cols-[auto_1fr] items-center gap-x-3 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Env key</dt>
            <dd className="flex items-center gap-1">
              <code className="font-mono" title={key.fingerprint}>
                {shortFingerprint(key.fingerprint)}
              </code>
              <CopyButton value={key.fingerprint} label="env key fingerprint" />
            </dd>
            <dt className="text-muted-foreground">Valid from</dt>
            <dd>
              <RelativeTime iso={key.not_before} />
            </dd>
          </dl>
        ) : (
          <Badge variant="destructive" className="shrink-0 self-start text-xs">
            Sealing unavailable
          </Badge>
        )}
      </CardContent>
    </Card>
  );
}
