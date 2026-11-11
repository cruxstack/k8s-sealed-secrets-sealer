import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Ban, RotateCcw } from "lucide-react";
import { toast } from "sonner";
import { extractApiError } from "@/api/client";
import { reinstateKey, revokeKey } from "@/api/queries/fleet";
import type { FleetKey } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { formatDateTime, shortFingerprint, timeAgo } from "@/lib/utils";
import { CopyButton } from "./CopyButton";

function Dash() {
  return (
    <span className="text-muted-foreground" aria-label="none">
      —
    </span>
  );
}

/** A key's status, as a badge with a word. */
function KeyStatusBadge({ fleetKey, now }: { fleetKey: FleetKey; now: Date }) {
  if (fleetKey.status === "revoked") {
    const by = fleetKey.revoked_by ? ` by ${fleetKey.revoked_by}` : "";
    return (
      <span className="flex flex-col items-start gap-0.5">
        <Badge variant="destructive">Revoked</Badge>
        {fleetKey.revoked_at && (
          <time
            className="text-xs whitespace-nowrap text-muted-foreground"
            dateTime={fleetKey.revoked_at}
            title={`Revoked${by}, ${formatDateTime(fleetKey.revoked_at)}`}
          >
            {by.trim() || "revoked"} {timeAgo(fleetKey.revoked_at, now)}
          </time>
        )}
      </span>
    );
  }
  if (fleetKey.future_dated) {
    return (
      <Badge
        variant="warning"
        title={`Valid only from ${formatDateTime(fleetKey.not_before)}; not used or restored until then`}
      >
        Future-dated
      </Badge>
    );
  }
  if (fleetKey.env_key) {
    return (
      <Badge variant="success" title="Values are sealed with it">
        Env key
      </Badge>
    );
  }
  return <Badge variant="outline">Active</Badge>;
}

function KeyRow({
  fleetKey,
  clusters,
  now,
  busy,
  onRevoke,
  onReinstate,
}: {
  fleetKey: FleetKey;
  clusters: number;
  now: Date;
  busy: boolean;
  onRevoke: () => void;
  onReinstate: () => void;
}) {
  const holders = fleetKey.holders ?? [];
  const short = shortFingerprint(fleetKey.fingerprint);
  const revoked = fleetKey.status === "revoked";
  return (
    <tr
      className={
        revoked
          ? "border-b border-border align-top text-muted-foreground last:border-0"
          : "border-b border-border align-top last:border-0"
      }
    >
      <th scope="row" className="px-4 py-2.5 text-left font-normal">
        <span className="flex items-center gap-1 whitespace-nowrap">
          <code className="font-mono text-xs" title={fleetKey.fingerprint}>
            {short}
          </code>
          <CopyButton value={fleetKey.fingerprint} label="key fingerprint" />
        </span>
      </th>
      <td className="px-4 py-3 whitespace-nowrap">
        <time dateTime={fleetKey.not_before}>
          {formatDateTime(fleetKey.not_before)}
        </time>
      </td>
      <td className="px-4 py-3 text-right whitespace-nowrap tabular-nums">
        {holders.length > 0 ? (
          <span title={holders.join("\n")}>
            {holders.length} of {clusters}
          </span>
        ) : (
          <Dash />
        )}
      </td>
      <td className="px-4 py-3 text-right whitespace-nowrap tabular-nums">
        {fleetKey.escrow_copies > 0 ? (
          <span
            title={`${fleetKey.escrow_copies} escrowed ${fleetKey.escrow_copies === 1 ? "copy" : "copies"}, each from another agent`}
          >
            {fleetKey.escrow_copies}
          </span>
        ) : (
          <span
            className={revoked ? undefined : "font-semibold text-warning"}
            title="No escrowed copy: clusters missing it cannot restore it"
          >
            0
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        <KeyStatusBadge fleetKey={fleetKey} now={now} />
      </td>
      <td className="px-4 py-2 text-right">
        {revoked ? (
          <Button
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={onReinstate}
            aria-label={`Reinstate key ${short}`}
          >
            <RotateCcw className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            Reinstate
          </Button>
        ) : (
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground hover:text-destructive"
            disabled={busy}
            onClick={onRevoke}
            aria-label={`Revoke key ${short}`}
          >
            <Ban className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            Revoke
          </Button>
        )}
      </td>
    </tr>
  );
}

/**
 * The env's keys, newest first, with how many clusters hold each, its
 * escrowed copies and its status. Admins revoke a key here, and reinstate
 * one, each after a dialog that says what it does.
 */
export function KeyTable({
  keys,
  clusters,
  now = new Date(),
}: {
  keys: FleetKey[];
  /** How many agents are registered, to say how many hold a key. */
  clusters: number;
  now?: Date;
}) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState<{
    key: FleetKey;
    action: "revoke" | "reinstate";
  } | null>(null);
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["fleet"] });
    // the env key may have moved, and with it whether sealing works
    void queryClient.invalidateQueries({ queryKey: ["status"] });
  };
  const revoke = useMutation({
    mutationFn: (k: FleetKey) => revokeKey(k.fingerprint),
    onSuccess: (_, k) => {
      setConfirming(null);
      toast(`Revoked ${shortFingerprint(k.fingerprint)}`, {
        description: "Rotate the values sealed with it if it may be exposed.",
      });
    },
    onSettled: refresh,
  });
  const reinstate = useMutation({
    mutationFn: (k: FleetKey) => reinstateKey(k.fingerprint),
    onSuccess: (_, k) => {
      setConfirming(null);
      toast(`Reinstated ${shortFingerprint(k.fingerprint)}`);
    },
    onSettled: refresh,
  });
  const pending = revoke.isPending || reinstate.isPending;

  return (
    <>
      <div className="overflow-x-auto rounded-xl border bg-card">
        <table className="w-full text-sm">
          <caption className="sr-only">
            Sealing keys in this environment
          </caption>
          <thead className="border-b border-border bg-muted/50 text-xs tracking-wide whitespace-nowrap text-muted-foreground uppercase">
            <tr>
              <th scope="col" className="px-4 py-3 text-left font-semibold">
                Key
              </th>
              <th scope="col" className="px-4 py-3 text-left font-semibold">
                Valid from
              </th>
              <th scope="col" className="px-4 py-3 text-right font-semibold">
                Held by
              </th>
              <th scope="col" className="px-4 py-3 text-right font-semibold">
                Escrowed
              </th>
              <th scope="col" className="px-4 py-3 text-left font-semibold">
                Status
              </th>
              <th scope="col" className="px-4 py-3 text-right font-semibold">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <KeyRow
                key={k.fingerprint}
                fleetKey={k}
                clusters={clusters}
                now={now}
                busy={
                  (revoke.isPending &&
                    revoke.variables?.fingerprint === k.fingerprint) ||
                  (reinstate.isPending &&
                    reinstate.variables?.fingerprint === k.fingerprint)
                }
                onRevoke={() => {
                  revoke.reset();
                  setConfirming({ key: k, action: "revoke" });
                }}
                onReinstate={() => {
                  reinstate.reset();
                  setConfirming({ key: k, action: "reinstate" });
                }}
              />
            ))}
          </tbody>
        </table>
      </div>

      <Dialog
        open={confirming !== null}
        onOpenChange={(o) => !o && !pending && setConfirming(null)}
      >
        <DialogContent>
          {confirming?.action === "revoke" && (
            <>
              <DialogHeader>
                <DialogTitle>Revoke this key?</DialogTitle>
                <DialogDescription>
                  The control plane stops using{" "}
                  <code
                    className="font-mono text-xs"
                    title={confirming.key.fingerprint}
                  >
                    {shortFingerprint(confirming.key.fingerprint)}
                  </code>
                  : nothing more is sealed with it, it is not restored to any
                  cluster, and no cluster counts as missing it.
                </DialogDescription>
              </DialogHeader>
              <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
                {confirming.key.env_key && (
                  <li>
                    <span className="font-medium text-foreground">
                      It is the env key.
                    </span>{" "}
                    Sealing moves to the newest other key every cluster holds,
                    or stops until there is one.
                  </li>
                )}
                <li>
                  Seals still running with it fail, and pending changes sealed
                  with it must be sealed again before a pull request. Pull
                  requests already open are not changed.
                </li>
                <li>
                  It does not remove the key from any cluster: clusters keep it
                  and still decrypt values sealed with it, as can anyone who has
                  a copy.
                </li>
                <li>
                  If the key may be exposed, rotate the values sealed with it:
                  seal new values, since git history keeps the old ciphertext.
                </li>
                <li>Its escrowed copies are kept, so you can reinstate it.</li>
              </ul>
              {revoke.error && (
                <p role="alert" className="text-sm text-destructive">
                  Could not revoke the key: {extractApiError(revoke.error)}
                </p>
              )}
              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline" disabled={revoke.isPending}>
                    Cancel
                  </Button>
                </DialogClose>
                <Button
                  variant="destructive"
                  disabled={revoke.isPending}
                  onClick={() => revoke.mutate(confirming.key)}
                >
                  Revoke key
                </Button>
              </DialogFooter>
            </>
          )}
          {confirming?.action === "reinstate" && (
            <>
              <DialogHeader>
                <DialogTitle>Reinstate this key?</DialogTitle>
                <DialogDescription>
                  The control plane uses{" "}
                  <code
                    className="font-mono text-xs"
                    title={confirming.key.fingerprint}
                  >
                    {shortFingerprint(confirming.key.fingerprint)}
                  </code>{" "}
                  again: it is restored to every cluster that lacks it, and
                  counts as missing there until it is.
                </DialogDescription>
              </DialogHeader>
              <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
                <li>
                  <span className="font-medium text-foreground">
                    It may become the env key.
                  </span>{" "}
                  Once every cluster holds it, it is the env key if it is the
                  newest key they share, and values are sealed with it.
                </li>
                <li>
                  Reinstate it only if it was revoked by mistake: anyone who has
                  a copy of an exposed key can decrypt what is sealed with it.
                </li>
              </ul>
              {reinstate.error && (
                <p role="alert" className="text-sm text-destructive">
                  Could not reinstate the key:{" "}
                  {extractApiError(reinstate.error)}
                </p>
              )}
              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline" disabled={reinstate.isPending}>
                    Cancel
                  </Button>
                </DialogClose>
                <Button
                  disabled={reinstate.isPending}
                  onClick={() => reinstate.mutate(confirming.key)}
                >
                  Reinstate key
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
