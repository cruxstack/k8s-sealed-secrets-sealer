import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  ExternalLink,
  GitPullRequest,
  Loader2,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { extractApiError } from "@/api/client";
import {
  discardSession,
  openPullRequest,
  removeChange,
  sessionQueryKey,
} from "@/api/queries/sessions";
import type { PendingChange, PullRequest, SealSession } from "@/api/types";
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
import {
  formatDateTime,
  safeHttpUrl,
  shortFingerprint,
  timeAgo,
} from "@/lib/utils";

function plural(n: number, one: string, many: string) {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/** The files a session changes, each with its keys, in order. */
function filesOf(changes: PendingChange[]): [string, string[]][] {
  const files = new Map<string, string[]>();
  for (const c of changes)
    files.set(c.path, [...(files.get(c.path) ?? []), c.key]);
  return [...files];
}

function ChangeRow({
  change,
  removing,
  onRemove,
  onSelectFile,
}: {
  change: PendingChange;
  removing: boolean;
  onRemove: () => void;
  onSelectFile: () => void;
}) {
  const agent = change.sealed_by.cluster || change.sealed_by.id;
  const targets = change.targets
    .map((t) => `${t.namespace}/${t.name}`)
    .join("\n");
  return (
    <tr className="group border-b border-border align-middle last:border-0">
      <th
        scope="row"
        className="px-5 py-2.5 text-left font-mono text-[13px] font-medium whitespace-nowrap"
      >
        {change.key}
      </th>
      <td className="max-w-0 px-3 py-2.5">
        <button
          type="button"
          onClick={onSelectFile}
          className="block max-w-full truncate rounded font-mono text-xs text-muted-foreground hover:text-foreground hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          title={`Show ${change.path}`}
        >
          {change.path}
        </button>
      </td>
      <td className="px-3 py-2.5 text-xs whitespace-nowrap" title={targets}>
        {plural(change.targets.length, "document", "documents")}
      </td>
      <td className="px-3 py-2.5 text-xs whitespace-nowrap text-muted-foreground">
        {agent} ·{" "}
        <code className="font-mono" title={change.fingerprint}>
          {shortFingerprint(change.fingerprint, 6)}
        </code>{" "}
        ·{" "}
        <time
          dateTime={change.sealed_at}
          title={formatDateTime(change.sealed_at)}
        >
          {timeAgo(change.sealed_at)}
        </time>
      </td>
      <td className="py-1.5 pr-3 text-right">
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-muted-foreground hover:text-destructive"
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

/**
 * The user's pending changes to a repository: open a pull request with
 * them, remove one, or discard them all.
 */
export function PendingChanges({
  owner,
  repo,
  session,
  sealing = false,
  onOpened,
  onSelectFile,
}: {
  owner: string;
  repo: string;
  session: SealSession;
  /** A seal is in progress on the page; its change is not listed yet. */
  sealing?: boolean;
  onOpened: (pr: PullRequest) => void;
  onSelectFile: (path: string) => void;
}) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState<"discard" | "open" | null>(null);
  const changes = session.changes ?? [];
  const files = filesOf(changes);
  const refresh = () => {
    void queryClient.invalidateQueries({
      queryKey: sessionQueryKey(owner, repo),
    });
    void queryClient.invalidateQueries({ queryKey: ["sessions"] });
  };
  const discard = useMutation({
    mutationFn: () => discardSession(owner, repo, session.id),
    onSuccess: () => {
      setConfirming(null);
      queryClient.setQueryData(sessionQueryKey(owner, repo), null);
      void queryClient.invalidateQueries({ queryKey: ["sessions"] });
      toast(
        `Discarded ${plural(changes.length, "pending change", "pending changes")}`,
      );
    },
  });
  const open = useMutation({
    mutationFn: () => openPullRequest(owner, repo, session.id),
    onSuccess: (pr) => {
      setConfirming(null);
      onOpened(pr);
      // the session ended with the pull request
      queryClient.setQueryData(sessionQueryKey(owner, repo), null);
      void queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
  const remove = useMutation({
    mutationFn: (change: PendingChange) =>
      removeChange(owner, repo, session.id, change.id),
    onSuccess: (_, change) =>
      toast(`Removed ${change.key}`, { description: change.path }),
    onSettled: refresh,
  });
  const openBlocked = sealing
    ? "Wait for the seal in progress to finish."
    : changes.length === 0
      ? "Seal a value first."
      : null;

  return (
    <section
      aria-labelledby="pending-heading"
      className="overflow-hidden rounded-xl border bg-card shadow-xs"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-3.5">
        <div className="space-y-0.5">
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
            , kept until{" "}
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
        <div className="flex shrink-0 gap-2">
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground hover:text-destructive"
            onClick={() => setConfirming("discard")}
          >
            Discard
          </Button>
          <Button
            size="sm"
            disabled={openBlocked !== null}
            title={openBlocked ?? undefined}
            onClick={() => {
              open.reset();
              setConfirming("open");
            }}
          >
            <GitPullRequest className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Open pull request
          </Button>
        </div>
      </div>

      {remove.error && (
        <p role="alert" className="px-5 py-3 text-sm text-destructive">
          Could not remove the change: {extractApiError(remove.error)}
        </p>
      )}
      {changes.length === 0 ? (
        <p className="px-5 py-4 text-sm text-muted-foreground">
          Nothing sealed yet. Values you seal wait here until you open a pull
          request with them.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[40rem] text-sm">
            <caption className="sr-only">
              Pending changes to {session.repository}
            </caption>
            <thead className="border-b border-border bg-muted/40 text-xs tracking-wide text-muted-foreground uppercase">
              <tr>
                <th scope="col" className="px-5 py-2 text-left font-semibold">
                  Key
                </th>
                <th
                  scope="col"
                  className="w-full px-3 py-2 text-left font-semibold"
                >
                  File
                </th>
                <th
                  scope="col"
                  className="px-3 py-2 text-left font-semibold whitespace-nowrap"
                >
                  Sealed for
                </th>
                <th
                  scope="col"
                  className="px-3 py-2 text-left font-semibold whitespace-nowrap"
                >
                  Sealed by
                </th>
                <th scope="col" className="py-2 pr-3">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {changes.map((c) => (
                <ChangeRow
                  key={c.id}
                  change={c}
                  removing={remove.isPending && remove.variables?.id === c.id}
                  onRemove={() => remove.mutate(c)}
                  onSelectFile={() => onSelectFile(c.path)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog
        open={confirming === "open"}
        onOpenChange={(o) =>
          !open.isPending && setConfirming(o ? "open" : null)
        }
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Open a pull request?</DialogTitle>
            <DialogDescription>
              One commit on a new branch from{" "}
              <code className="font-mono">{session.branch}</code> at{" "}
              <code className="font-mono">{session.commit.slice(0, 7)}</code>{" "}
              writes {plural(changes.length, "sealed value", "sealed values")}{" "}
              into {plural(files.length, "file", "files")}, changing only{" "}
              <code className="font-mono">spec.encryptedData</code>. The GitHub
              App opens the pull request into{" "}
              <code className="font-mono">{session.branch}</code> and names you
              as its requester; your pending changes are then cleared.
            </DialogDescription>
          </DialogHeader>
          <ul
            aria-label="Files in the pull request"
            className="max-h-48 space-y-2 overflow-y-auto rounded-lg border border-border bg-muted/40 p-3 text-sm"
          >
            {files.map(([path, keys]) => (
              <li key={path} className="space-y-1">
                <div
                  className="truncate font-mono text-xs font-medium"
                  title={path}
                >
                  {path}
                </div>
                <div className="flex flex-wrap gap-1">
                  {keys.map((k) => (
                    <code
                      key={k}
                      className="rounded bg-background px-1.5 py-0.5 font-mono text-xs"
                    >
                      {k}
                    </code>
                  ))}
                </div>
              </li>
            ))}
          </ul>
          {open.error && (
            <p role="alert" className="text-sm text-destructive">
              Could not open the pull request: {extractApiError(open.error)}
            </p>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" disabled={open.isPending}>
                Cancel
              </Button>
            </DialogClose>
            <Button disabled={open.isPending} onClick={() => open.mutate()}>
              {open.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <GitPullRequest className="mr-2 h-4 w-4" aria-hidden />
              )}
              {open.isPending ? "Opening…" : "Open pull request"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={confirming === "discard"}
        onOpenChange={(o) => setConfirming(o ? "discard" : null)}
      >
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

/** Says a pull request was opened, with the way to it. */
export function OpenedDialog({
  pr,
  onClose,
}: {
  pr: PullRequest | null;
  onClose: () => void;
}) {
  const url = safeHttpUrl(pr?.url);
  return (
    <Dialog open={pr !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md text-center">
        {pr && (
          <>
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-success/15">
              <CheckCircle2
                className="h-8 w-8 text-success"
                aria-hidden="true"
              />
            </div>
            <DialogHeader className="space-y-2 pr-0 text-center">
              <DialogTitle className="text-xl">
                Pull request #{pr.number} is open
              </DialogTitle>
              <DialogDescription className="space-y-1">
                <span className="block font-medium text-foreground">
                  {pr.title}
                </span>
                <span className="block">
                  On{" "}
                  <code className="font-mono text-xs break-all">
                    {pr.branch}
                  </code>
                </span>
              </DialogDescription>
            </DialogHeader>
            <div className="flex flex-col gap-2 pt-2">
              {url && (
                <Button asChild size="lg">
                  <a href={url} target="_blank" rel="noopener noreferrer">
                    View pull request
                    <ExternalLink className="ml-2 h-4 w-4" aria-hidden="true" />
                  </a>
                </Button>
              )}
              <Button variant="outline" onClick={onClose}>
                Keep sealing
              </Button>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
