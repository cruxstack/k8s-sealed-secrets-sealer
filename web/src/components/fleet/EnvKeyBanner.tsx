import { AlertTriangle, KeyRound } from "lucide-react";
import type { Fleet } from "@/api/types";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn, formatDateTime, shortFingerprint } from "@/lib/utils";
import { CopyButton } from "./CopyButton";

/** The env and its key state: the env key, or a warning that there is none. */
export function EnvKeyBanner({ fleet }: { fleet: Fleet }) {
  const key = fleet.env_key;
  const inSync = fleet.keys_in_sync && key !== null;

  return (
    <Card
      role="region"
      aria-label="Environment key"
      className={cn(!inSync && "border-warning/60")}
    >
      <CardContent className="flex flex-col gap-4 p-6 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              "flex h-10 w-10 items-center justify-center rounded-lg",
              inSync
                ? "bg-primary/10 text-primary"
                : "bg-warning/15 text-warning",
            )}
          >
            {inSync ? (
              <KeyRound className="h-5 w-5" aria-hidden="true" />
            ) : (
              <AlertTriangle className="h-5 w-5" aria-hidden="true" />
            )}
          </div>
          <div>
            <h1 className="text-xl font-bold">
              Environment <span className="font-mono">{fleet.env}</span>
            </h1>
            <p className="text-sm text-muted-foreground">
              Values are sealed with the newest key every cluster holds.
            </p>
          </div>
        </div>

        {inSync && key ? (
          <dl className="grid grid-cols-[auto_1fr] items-center gap-x-3 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Env key</dt>
            <dd className="flex items-center gap-1">
              <code className="font-mono" title={key.fingerprint}>
                {shortFingerprint(key.fingerprint)}
              </code>
              <CopyButton value={key.fingerprint} label="env key fingerprint" />
            </dd>
            <dt className="text-muted-foreground">Valid from</dt>
            <dd>
              <time dateTime={key.not_before}>
                {formatDateTime(key.not_before)}
              </time>
            </dd>
          </dl>
        ) : (
          <div role="alert" className="flex flex-col gap-1 md:items-end">
            <Badge variant="warning" className="text-xs">
              Keys out of sync
            </Badge>
            <p className="max-w-md text-sm text-muted-foreground md:text-right">
              No key is held by every cluster yet, so sealing is unavailable.
              The table shows which keys each cluster is missing.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
