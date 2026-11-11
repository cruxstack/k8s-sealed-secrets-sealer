import { useId, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Ban, RotateCcw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { deleteKey, reinstateKey, revokeKey } from "@/api/queries/fleet";
import type { FleetAgent, FleetKey } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { IconButton } from "@/components/ui/icon-button";
import { RelativeTime } from "@/components/ui/relative-time";
import {
  Dash,
  Table,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn, formatDateTime, shortFingerprint } from "@/lib/utils";
import { CopyButton } from "./CopyButton";
import {
  DeleteKeyDialog,
  Fingerprint,
  ReinstateKeyDialog,
  RevokeKeyDialog,
} from "./KeyDialogs";
import { ReferencesCell, ReferencesDetail } from "./KeyReferences";
import { noneCount, plural } from "./references";

/** The columns of the key table, for the row under a key that spans them. */
const COLUMNS = 7;

/** Who changed a key's status and when, under its badge. */
function StatusBy({
  verb,
  by,
  at,
  now,
}: {
  verb: string;
  by?: string;
  at?: string;
  now: Date;
}) {
  if (!at) return null;
  const who = by ? ` by ${by}` : "";
  return (
    <span className="text-xs whitespace-nowrap text-muted-foreground">
      {who.trim() || verb.toLowerCase()}{" "}
      <RelativeTime
        iso={at}
        now={now}
        past
        describe={(abs) => `${verb}${who}, ${abs}`}
      />
    </span>
  );
}

/**
 * A deleted key's status: who deleted it, when its escrowed copies are
 * purged (until then it can be reinstated), and the clusters it is still
 * being removed from.
 */
function DeletedStatus({ fleetKey, now }: { fleetKey: FleetKey; now: Date }) {
  const holders = fleetKey.holders ?? [];
  return (
    <span className="flex flex-col items-start gap-0.5">
      <Badge variant="destructive">Deleted</Badge>
      <StatusBy
        verb="Deleted"
        by={fleetKey.deleted_by}
        at={fleetKey.deleted_at}
        now={now}
      />
      {fleetKey.purge_at ? (
        <span className="text-xs whitespace-nowrap text-muted-foreground">
          escrow purged{" "}
          <RelativeTime
            iso={fleetKey.purge_at}
            now={now}
            past={fleetKey.purged}
            describe={(at) =>
              fleetKey.purged
                ? `Escrowed copies purged ${at}: it cannot be reinstated`
                : `Escrowed copies purged ${at}; it can be reinstated until then`
            }
          />
        </span>
      ) : (
        fleetKey.purged && (
          <span className="text-xs whitespace-nowrap text-muted-foreground">
            escrow purged
          </span>
        )
      )}
      {holders.length > 0 && (
        <span
          className="text-xs whitespace-nowrap text-info"
          title={holders.join("\n")}
        >
          removing from {plural(holders.length, "cluster")}
        </span>
      )}
    </span>
  );
}

/** A key's status, as a badge with a word. */
function KeyStatusBadge({ fleetKey, now }: { fleetKey: FleetKey; now: Date }) {
  if (fleetKey.status === "deleted") {
    return <DeletedStatus fleetKey={fleetKey} now={now} />;
  }
  if (fleetKey.status === "revoked") {
    return (
      <span className="flex flex-col items-start gap-0.5">
        <Badge variant="destructive">Revoked</Badge>
        <StatusBy
          verb="Revoked"
          by={fleetKey.revoked_by}
          at={fleetKey.revoked_at}
          now={now}
        />
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

type KeyAction = "revoke" | "reinstate" | "delete";

/**
 * Why each action cannot be taken on a key now; an action left out can be.
 * Revoke takes an active key; delete, a revoked one nothing refers to, as
 * the control plane says (`deletable`); reinstate, a revoked one, or a
 * deleted one until its escrowed copies are purged.
 */
export function unavailable(k: FleetKey): Partial<Record<KeyAction, string>> {
  const why: Partial<Record<KeyAction, string>> = {};
  if (k.status === "revoked") why.revoke = "Already revoked.";
  if (k.status === "deleted") why.revoke = "Deleted.";
  if (k.status === "active") why.reinstate = "Not revoked.";
  if (k.status === "deleted" && k.purged) {
    why.reinstate = "Escrowed copies were purged.";
  }
  if (!k.deletable) {
    // the control plane says why; these cover one that does not
    why.delete =
      k.delete_blocked ??
      (k.status === "active"
        ? "Revoke the key first."
        : k.status === "deleted"
          ? "Already deleted."
          : k.references.values > 0
            ? `${plural(k.references.values, "value is", "values are")} sealed with it.`
            : "It cannot be deleted now.");
  }
  return why;
}

/**
 * Revoke, Delete and Reinstate, as icons in the same places on every key's
 * row, grayed out with the reason when they do not apply, so the column
 * never changes width and a key's row says what can be done to it.
 */
function KeyActions({
  fleetKey,
  onAction,
}: {
  fleetKey: FleetKey;
  onAction: (action: KeyAction) => void;
}) {
  const short = shortFingerprint(fleetKey.fingerprint);
  const why = unavailable(fleetKey);
  // the destructive color says what a click would do, so only when it can
  const destructive = (action: KeyAction) =>
    why[action] === undefined &&
    "hover:text-destructive focus-visible:text-destructive";
  return (
    <span className="inline-flex items-center gap-1">
      <IconButton
        label="Revoke"
        reason={why.revoke}
        aria-label={`Revoke key ${short}`}
        className={cn("text-muted-foreground", destructive("revoke"))}
        onClick={() => onAction("revoke")}
      >
        <Ban className="h-4 w-4" aria-hidden="true" />
      </IconButton>
      <IconButton
        label="Delete"
        reason={why.delete}
        aria-label={`Delete key ${short}`}
        className={cn("text-muted-foreground", destructive("delete"))}
        onClick={() => onAction("delete")}
      >
        <Trash2 className="h-4 w-4" aria-hidden="true" />
      </IconButton>
      <IconButton
        label="Reinstate"
        reason={why.reinstate}
        aria-label={`Reinstate key ${short}`}
        className="text-muted-foreground"
        onClick={() => onAction("reinstate")}
      >
        <RotateCcw className="h-4 w-4" aria-hidden="true" />
      </IconButton>
    </span>
  );
}

function KeyRow({
  fleetKey,
  agents,
  counting,
  now,
  onAction,
}: {
  fleetKey: FleetKey;
  agents: FleetAgent[];
  counting: boolean;
  now: Date;
  onAction: (action: KeyAction) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const detailId = useId();
  const holders = fleetKey.holders ?? [];
  const inUse = fleetKey.status === "active";
  return (
    <>
      <TableRow
        className={cn(
          !inUse && "text-muted-foreground",
          // the row under it belongs to this one
          expanded && "border-b-0",
        )}
      >
        <th scope="row" className="px-4 py-3 text-left font-normal">
          <span className="flex items-center gap-1 whitespace-nowrap">
            <Fingerprint value={fleetKey.fingerprint} className="text-xs" />
            <CopyButton value={fleetKey.fingerprint} label="key fingerprint" />
          </span>
        </th>
        <TableCell className="whitespace-nowrap">
          <RelativeTime iso={fleetKey.not_before} now={now} />
        </TableCell>
        <TableCell className="text-right whitespace-nowrap tabular-nums">
          {holders.length > 0 ? (
            <span title={holders.join("\n")}>
              {holders.length} of {agents.length}
            </span>
          ) : (
            <Dash />
          )}
        </TableCell>
        <TableCell className="text-right whitespace-nowrap tabular-nums">
          {fleetKey.escrow_copies > 0 ? (
            <span
              title={`${plural(fleetKey.escrow_copies, "escrowed copy", "escrowed copies")}, each from another agent`}
            >
              {fleetKey.escrow_copies}
            </span>
          ) : (
            <span
              className={inUse ? "font-semibold text-warning" : undefined}
              title="No escrowed copy: clusters missing it cannot restore it"
            >
              0
            </span>
          )}
        </TableCell>
        <TableCell className="text-right">
          <ReferencesCell
            fleetKey={fleetKey}
            counting={counting}
            expanded={expanded}
            detailId={detailId}
            onToggle={() => setExpanded((e) => !e)}
          />
        </TableCell>
        <TableCell>
          <KeyStatusBadge fleetKey={fleetKey} now={now} />
        </TableCell>
        <TableCell className="py-2 text-right whitespace-nowrap">
          <KeyActions fleetKey={fleetKey} onAction={onAction} />
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow id={detailId} className="bg-muted/30">
          <td colSpan={COLUMNS} className="px-4 py-3">
            <ReferencesDetail fleetKey={fleetKey} agents={agents} now={now} />
          </td>
        </TableRow>
      )}
    </>
  );
}

/**
 * The env's keys, newest first, with how many clusters hold each, its
 * escrowed copies, the values sealed with it and its status. Admins revoke
 * a key here, delete a revoked one nothing refers to, and reinstate either,
 * each after a dialog that says what it does.
 */
export function KeyTable({
  keys,
  agents,
  now = new Date(),
}: {
  keys: FleetKey[];
  /** The registered agents: how many, and why a cluster did not count. */
  agents: FleetAgent[];
  now?: Date;
}) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState<{
    key: FleetKey;
    action: KeyAction;
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
      toast.success(
        <span>
          Revoked <Fingerprint value={k.fingerprint} />
        </span>,
        {
          description: "Rotate the values sealed with it if it may be exposed.",
        },
      );
    },
    onSettled: refresh,
  });
  const reinstate = useMutation({
    mutationFn: (k: FleetKey) => reinstateKey(k.fingerprint),
    onSuccess: (_, k) => {
      setConfirming(null);
      toast.success(
        <span>
          Reinstated <Fingerprint value={k.fingerprint} />
        </span>,
        k.status === "deleted"
          ? {
              description: "Key sync restores it to every cluster from escrow.",
            }
          : undefined,
      );
    },
    onSettled: refresh,
  });
  const remove = useMutation({
    mutationFn: (k: FleetKey) => deleteKey(k.fingerprint),
    onSuccess: (_, k) => {
      setConfirming(null);
      toast.success(
        <span>
          Deleted <Fingerprint value={k.fingerprint} />
        </span>,
        {
          description:
            "Each cluster removes it at its next check-in. Reinstate it within 30 days to undo this.",
        },
      );
    },
    onSettled: refresh,
  });
  const mutations = { revoke, reinstate, delete: remove };
  const pending = revoke.isPending || reinstate.isPending || remove.isPending;
  const counting = !noneCount(agents);

  return (
    <>
      {/* cells are centred, and every row has the same actions, so
          nothing shifts when a key is revoked, deleted or reinstated */}
      <Table className="[&_td]:align-middle [&_th]:align-middle">
        <caption className="sr-only">Sealing keys in this env</caption>
        <TableHeader>
          <tr>
            <TableHead>Key</TableHead>
            <TableHead>Valid from</TableHead>
            <TableHead className="text-right">Held by</TableHead>
            <TableHead className="text-right">Escrowed</TableHead>
            <TableHead className="text-right">References</TableHead>
            <TableHead>Status</TableHead>
            {/* as narrow as the three icons, the same on every row, and
                right-aligned like them */}
            <TableHead className="w-px text-right">Actions</TableHead>
          </tr>
        </TableHeader>
        <tbody>
          {keys.map((k) => (
            <KeyRow
              key={k.fingerprint}
              fleetKey={k}
              agents={agents}
              counting={counting}
              now={now}
              onAction={(action) => {
                mutations[action].reset();
                setConfirming({ key: k, action });
              }}
            />
          ))}
        </tbody>
      </Table>

      <Dialog
        open={confirming !== null}
        onOpenChange={(o) => !o && !pending && setConfirming(null)}
      >
        <DialogContent>
          {confirming?.action === "revoke" && (
            <RevokeKeyDialog
              fleetKey={confirming.key}
              request={revoke}
              onConfirm={() => revoke.mutate(confirming.key)}
            />
          )}
          {confirming?.action === "reinstate" && (
            <ReinstateKeyDialog
              fleetKey={confirming.key}
              request={reinstate}
              now={now}
              onConfirm={() => reinstate.mutate(confirming.key)}
            />
          )}
          {confirming?.action === "delete" && (
            <DeleteKeyDialog
              fleetKey={confirming.key}
              request={remove}
              now={now}
              onConfirm={() => remove.mutate(confirming.key)}
            />
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
