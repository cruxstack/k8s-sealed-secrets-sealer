import type { ReactNode } from "react";
import { extractApiError } from "@/api/client";
import type { FleetKey } from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  DialogClose,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { RelativeTime } from "@/components/ui/relative-time";
import { cn, shortFingerprint } from "@/lib/utils";
import { oldestCount } from "./references";

/** A fingerprint, short, in monospace, with the full one in its title. */
export function Fingerprint({
  value,
  className,
}: {
  value: string;
  className?: string;
}) {
  return (
    <code className={cn("font-mono", className)} title={value}>
      {shortFingerprint(value)}
    </code>
  );
}

/** Where a confirm dialog's request stands. */
export interface Request {
  isPending: boolean;
  error: Error | null;
}

/** A point in a dialog's list, led by a short phrase in the text color. */
export function Point({
  lead,
  children,
}: {
  lead?: string;
  children: ReactNode;
}) {
  return (
    <li>
      {lead && (
        <>
          <span className="font-medium text-foreground">{lead}</span>{" "}
        </>
      )}
      {children}
    </li>
  );
}

export function Points({ children }: { children: ReactNode }) {
  return (
    <ul className="list-disc space-y-1.5 pl-5 text-sm text-muted-foreground">
      {children}
    </ul>
  );
}

/** The server's refusal, then Cancel and the confirm button. */
export function Confirm({
  request,
  failed,
  label,
  dismiss = "Cancel",
  destructive = false,
  onConfirm,
}: {
  request: Request;
  /** What could not be done: "Could not {failed}: {why}". */
  failed: string;
  label: string;
  /** The way back, where "Cancel" would read as the action. */
  dismiss?: string;
  destructive?: boolean;
  onConfirm: () => void;
}) {
  return (
    <>
      {request.error && (
        <p role="alert" className="text-sm text-destructive">
          Could not {failed}: {extractApiError(request.error)}
        </p>
      )}
      <DialogFooter>
        <DialogClose asChild>
          <Button variant="outline" disabled={request.isPending}>
            {dismiss}
          </Button>
        </DialogClose>
        <Button
          variant={destructive ? "destructive" : "default"}
          disabled={request.isPending}
          onClick={onConfirm}
        >
          {label}
        </Button>
      </DialogFooter>
    </>
  );
}

/** What revoking does and does not do, before it is confirmed. */
export function RevokeKeyDialog({
  fleetKey,
  request,
  onConfirm,
}: {
  fleetKey: FleetKey;
  request: Request;
  onConfirm: () => void;
}) {
  return (
    <>
      <DialogHeader>
        <DialogTitle>Revoke This Key?</DialogTitle>
        <DialogDescription>
          The control plane stops using{" "}
          <Fingerprint value={fleetKey.fingerprint} className="text-xs" />:
          nothing more is sealed with it, it is not restored to any cluster, and
          no cluster counts as missing it.
        </DialogDescription>
      </DialogHeader>
      <Points>
        {fleetKey.env_key && (
          <Point lead="It is the env key.">
            Sealing moves to the newest other key every cluster holds, or stops
            until there is one.
          </Point>
        )}
        <Point>
          Seals still running with it fail, and pending changes sealed with it
          must be sealed again before a pull request. Pull requests already open
          are not changed.
        </Point>
        <Point>
          It does not remove the key from any cluster: clusters keep it and
          still decrypt values sealed with it, as can anyone who has a copy.
        </Point>
        <Point>
          If the key may be exposed, rotate the values sealed with it: seal new
          values, since git history keeps the old ciphertext.
        </Point>
        <Point>Its escrowed copies are kept, so you can reinstate it.</Point>
      </Points>
      <Confirm
        request={request}
        failed="revoke the key"
        label="Revoke Key"
        destructive
        onConfirm={onConfirm}
      />
    </>
  );
}

/**
 * What reinstating does, before it is confirmed. A deleted key comes back
 * from escrow, so its controllers restart; a revoked one is still in the
 * clusters.
 */
export function ReinstateKeyDialog({
  fleetKey,
  request,
  now,
  onConfirm,
}: {
  fleetKey: FleetKey;
  request: Request;
  now: Date;
  onConfirm: () => void;
}) {
  const deleted = fleetKey.status === "deleted";
  return (
    <>
      <DialogHeader>
        <DialogTitle>
          {deleted ? "Reinstate This Deleted Key?" : "Reinstate This Key?"}
        </DialogTitle>
        {deleted ? (
          <DialogDescription>
            The control plane uses{" "}
            <Fingerprint value={fleetKey.fingerprint} className="text-xs" />{" "}
            again, and key sync restores it from escrow to every cluster; each
            controller restarts once to load it. Its escrowed copies are kept
            rather than purged
            {fleetKey.purge_at && (
              <>
                {" "}
                <RelativeTime
                  iso={fleetKey.purge_at}
                  now={now}
                  describe={(at) => `Purged ${at} unless reinstated`}
                />
              </>
            )}
            .
          </DialogDescription>
        ) : (
          <DialogDescription>
            The control plane uses{" "}
            <Fingerprint value={fleetKey.fingerprint} className="text-xs" />{" "}
            again: it is restored to every cluster that lacks it, and counts as
            missing there until it is.
          </DialogDescription>
        )}
      </DialogHeader>
      <Points>
        <Point lead="It may become the env key.">
          Once every cluster holds it, it is the env key if it is the newest key
          they share, and values are sealed with it.
        </Point>
        <Point>
          Reinstate it only if it was {deleted ? "deleted" : "revoked"} by
          mistake: anyone who has a copy of an exposed key can decrypt what is
          sealed with it.
        </Point>
      </Points>
      <Confirm
        request={request}
        failed="reinstate the key"
        label="Reinstate Key"
        onConfirm={onConfirm}
      />
    </>
  );
}

/**
 * What deleting does, what the reference count it rests on cannot see, and
 * how long it can be undone, before it is confirmed.
 */
export function DeleteKeyDialog({
  fleetKey,
  request,
  now,
  onConfirm,
}: {
  fleetKey: FleetKey;
  request: Request;
  now: Date;
  onConfirm: () => void;
}) {
  const oldest = oldestCount(fleetKey.references);
  return (
    <>
      <DialogHeader>
        <DialogTitle>Delete This Key?</DialogTitle>
        <DialogDescription>
          <Fingerprint value={fleetKey.fingerprint} className="text-xs" /> is
          removed from every cluster, and each controller restarts once to drop
          it.
        </DialogDescription>
      </DialogHeader>
      <Points>
        <Point lead="No cluster refers to it.">
          Every cluster counted the values in its SealedSecrets, and none was
          sealed with it
          {oldest && (
            <>
              ; the oldest count was taken{" "}
              <RelativeTime
                iso={oldest}
                now={now}
                past
                describe={(at) => `Counted ${at}`}
              />
            </>
          )}
          .
        </Point>
        <Point lead="You can undo it for 30 days.">
          Its escrowed copies are kept until then, and Reinstate restores the
          key to every cluster. After that it is gone for good.
        </Point>
        <Point>
          The count cannot see values in git that are not deployed to any
          cluster, or pull requests opened before the key was revoked that merge
          later. Once deployed, those values would not decrypt.
        </Point>
        <Point>
          Afterwards, watch the clusters&apos; unmatched counts under Sealed
          values in the agents table: they are values no key in the cluster
          decrypts.
        </Point>
      </Points>
      <Confirm
        request={request}
        failed="delete the key"
        label="Delete Key"
        destructive
        onConfirm={onConfirm}
      />
    </>
  );
}
