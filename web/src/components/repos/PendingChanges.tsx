import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { extractApiError } from "@/api/client";
import {
  discardSession,
  removeChange,
  sessionQueryKey,
} from "@/api/queries/sessions";
import type { PendingChange, SealSession } from "@/api/types";
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

function plural(n: number, one: string, many: string) {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

function ChangeRow({
  change,
  onRemove,
  removing,
}: {
  change: PendingChange;
  onRemove: () => void;
  removing: boolean;
}) {
  const agent = change.sealed_by.cluster || change.sealed_by.id;
  const targets = change.targets
    .map((t) => `${t.namespace}/${t.name}`)
    .join("\n");
  return (
    <tr className="border-b border-border align-top last:border-0">
      <th
        scope="row"
        className="truncate px-4 py-3 text-left font-mono text-sm font-medium whitespace-nowrap"
        title={change.path}
      >
        {change.path}
      </th>
      <td className="px-4 py-3">
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
          {change.key}
        </code>
      </td>
      <td className="px-4 py-3 whitespace-nowrap" title={targets}>
        {plural(change.targets.length, "document", "documents")}
      </td>
      <td className="px-4 py-3 text-xs">
        <div className="whitespace-nowrap">{agent}</div>
        <div className="text-muted-foreground">
          <code className="font-mono" title={change.fingerprint}>
            {shortFingerprint(change.fingerprint, 8)}
          </code>{" "}
          ·{" "}
          <time
            dateTime={change.sealed_at}
            title={formatDateTime(change.sealed_at)}
          >
            {timeAgo(change.sealed_at)}
          </time>
        </div>
      </td>
      <td className="px-2 py-2 text-right">
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={onRemove}
          disabled={removing}
          aria-label={`Remove ${change.key} from ${change.path}`}
          title="Remove this change"
        >
          <Trash2 className="h-4 w-4" aria-hidden="true" />
        </Button>
      </td>
    </tr>
  );
}

/** The user's pending changes to a repository, with discard and remove. */
export function PendingChanges({
  owner,
  repo,
  session,
}: {
  owner: string;
  repo: string;
  session: SealSession;
}) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const changes = session.changes ?? [];
  const refresh = () => {
    void queryClient.invalidateQueries({
      queryKey: sessionQueryKey(owner, repo),
    });
    void queryClient.invalidateQueries({ queryKey: ["sessions"] });
  };
  const discard = useMutation({
    mutationFn: () => discardSession(owner, repo, session.id),
    onSuccess: () => {
      setConfirming(false);
      queryClient.setQueryData(sessionQueryKey(owner, repo), null);
      void queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
  const remove = useMutation({
    mutationFn: (changeId: string) =>
      removeChange(owner, repo, session.id, changeId),
    onSettled: refresh,
  });
  const error = remove.error ?? null;

  return (
    <section
      aria-labelledby="pending-heading"
      className="overflow-hidden rounded-xl border bg-card"
    >
      <div className="flex items-start justify-between gap-4 border-b border-border px-4 py-3">
        <div className="space-y-1">
          <h2
            id="pending-heading"
            className="flex items-center gap-2 text-sm font-semibold"
          >
            Pending changes
            <Badge variant={changes.length > 0 ? "default" : "secondary"}>
              {changes.length}
            </Badge>
          </h2>
          <p className="text-xs text-muted-foreground">
            Based on <code className="font-mono">{session.branch}</code> at{" "}
            <code className="font-mono" title={session.commit}>
              {session.commit.slice(0, 7)}
            </code>
            . Kept until{" "}
            <time
              dateTime={session.expires_at}
              title={formatDateTime(session.expires_at)}
            >
              {new Date(session.expires_at).toLocaleTimeString(undefined, {
                hour: "2-digit",
                minute: "2-digit",
              })}
            </time>
            ; sealing again extends that.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
          Discard
        </Button>
      </div>

      {error && (
        <p role="alert" className="px-4 py-3 text-sm text-destructive">
          Could not remove the change: {extractApiError(error)}
        </p>
      )}
      {changes.length === 0 ? (
        <p className="px-4 py-3 text-sm text-muted-foreground">
          Nothing sealed yet. Seal a value into one of the files below.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[48rem] table-fixed text-sm">
            <caption className="sr-only">
              Pending changes to {session.repository}
            </caption>
            <colgroup>
              <col className="w-[38%]" />
              <col className="w-[18%]" />
              <col className="w-[14%]" />
              <col className="w-[24%]" />
              <col className="w-[6%]" />
            </colgroup>
            <thead className="border-b border-border bg-muted/50 text-xs tracking-wide text-muted-foreground uppercase">
              <tr>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  File
                </th>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Key
                </th>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Sealed for
                </th>
                <th scope="col" className="px-4 py-2 text-left font-semibold">
                  Sealed by
                </th>
                <th scope="col" className="px-2 py-2">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {changes.map((c) => (
                <ChangeRow
                  key={c.id}
                  change={c}
                  removing={remove.isPending && remove.variables === c.id}
                  onRemove={() => remove.mutate(c.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={confirming} onOpenChange={setConfirming}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Discard pending changes?</DialogTitle>
            <DialogDescription>
              {changes.length === 0
                ? `This closes your session for ${session.repository}.`
                : `This removes ${plural(changes.length, "pending change", "pending changes")} to ${session.repository}. Nothing was committed, so nothing changes on GitHub.`}
            </DialogDescription>
          </DialogHeader>
          {discard.error && (
            <p role="alert" className="text-sm text-destructive">
              Could not discard: {extractApiError(discard.error)}
            </p>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button
              variant="destructive"
              disabled={discard.isPending}
              onClick={() => discard.mutate()}
            >
              Discard
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}
