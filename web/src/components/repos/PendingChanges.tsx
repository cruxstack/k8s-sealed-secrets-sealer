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
import { regionList } from "./keys";
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
import { formatDateTime, safeHttpUrl, timeAgo } from "@/lib/utils";

function plural(n: number, one: string, many: string) {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/** A change's key, with the regions it was sealed for when limited. */
function keyIn(c: PendingChange): string {
  return c.regions?.length ? `${c.key} in ${regionList(c.regions)}` : c.key;
}

/** The files a session changes, each with its keys, in order. */
function filesOf(changes: PendingChange[]): [string, string[]][] {
  const files = new Map<string, string[]>();
  for (const c of changes)
    files.set(c.path, [...(files.get(c.path) ?? []), keyIn(c)]);
  return [...files];
}

function ChangeItem({
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
    <li className="flex items-start gap-2 py-2 pr-2 pl-4">
      <div className="min-w-0 flex-1 space-y-0.5">
        <p className="flex min-w-0 items-center gap-1.5">
          <code className="truncate font-mono text-[13px] font-medium">
            {change.key}
          </code>
          {change.regions?.map((r) => (
            <Badge
              key={r}
              variant="outline"
              className="shrink-0 font-mono"
              title={`Sealed for ${r} only`}
            >
              {r}
            </Badge>
          ))}
          {change.key_revoked && (
            <Badge
              variant="warning"
              className="shrink-0"
              title="Sealed with a key an admin has since revoked. Seal the value again, or remove it, before opening a pull request."
            >
              Seal again
            </Badge>
          )}
        </p>
        <button
          type="button"
          onClick={onSelectFile}
          className="block max-w-full truncate rounded font-mono text-xs text-muted-foreground hover:text-foreground hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          title={`Show ${change.path}`}
        >
          {change.path}
        </button>
        <p className="text-xs text-muted-foreground">
          <span title={targets}>
            {plural(change.targets.length, "document", "documents")}
            {change.regions?.length ? ` in ${regionList(change.regions)}` : ""}
          </span>{" "}
          ·{" "}
          <time
            dateTime={change.sealed_at}
            title={`Sealed by ${agent} with ${change.fingerprint}, ${formatDateTime(change.sealed_at)}`}
          >
            {timeAgo(change.sealed_at)}
          </time>
        </p>
      </div>
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8 shrink-0 text-muted-foreground hover:text-destructive"
        onClick={onRemove}
        disabled={removing}
        aria-label={`Remove ${keyIn(change)} from ${change.path}`}
        title="Remove this change"
      >
        <Trash2 className="h-4 w-4" aria-hidden="true" />
      </Button>
    </li>
  );
}

const NOTHING_YET =
  "Nothing sealed yet. Values you seal wait here until you open a pull request with them.";

interface ChangesProps {
  owner: string;
  repo: string;
  session: SealSession;
  /** A seal is in progress on the page; its change is not listed yet. */
  sealing?: boolean;
  onOpened: (pr: PullRequest) => void;
  onSelectFile: (path: string) => void;
}

function Heading({ count }: { count: number }) {
  return (
    <h2
      id="pending-heading"
      className="flex items-center gap-2 text-sm font-semibold"
    >
      Pending changes
      <Badge variant={count > 0 ? "default" : "secondary"}>{count}</Badge>
    </h2>
  );
}

/**
 * The user's pending changes to a repository, like a cart beside the files:
 * open a pull request with them, remove one, or discard them all. Without a
 * session it says what will gather here.
 */
export function PendingChanges({
  session,
  ...props
}: Omit<ChangesProps, "session"> & { session: SealSession | null }) {
  if (session) return <SessionChanges session={session} {...props} />;
  return (
    <section
      aria-labelledby="pending-heading"
      className="shrink-0 overflow-hidden rounded-xl border bg-card shadow-xs"
    >
      <div className="border-b border-border px-4 py-3">
        <Heading count={0} />
      </div>
      <p className="px-4 py-3 text-sm text-muted-foreground">{NOTHING_YET}</p>
    </section>
  );
}

function SessionChanges({
  owner,
  repo,
  session,
  sealing = false,
  onOpened,
  onSelectFile,
}: ChangesProps) {
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
      toast(`Removed ${keyIn(change)}`, { description: change.path }),
    onSettled: refresh,
  });
  const openBlocked = sealing
    ? "Wait for the seal in progress to finish."
    : changes.length === 0
      ? "Seal a value first."
      : changes.some((c) => c.key_revoked)
        ? "Seal again, or remove, the values sealed with a revoked key."
        : null;

  return (
    <section
      aria-labelledby="pending-heading"
      className="shrink-0 overflow-hidden rounded-xl border bg-card shadow-xs"
    >
      <div className="space-y-0.5 border-b border-border px-4 py-3">
        <Heading count={changes.length} />
        <p className="text-xs text-muted-foreground">
          On <code className="font-mono">{session.branch}</code> at{" "}
          <code className="font-mono" title={session.commit}>
            {session.commit.slice(0, 7)}
          </code>
          , kept until{" "}
          <time
            dateTime={session.expires_at}
            title={`${formatDateTime(session.expires_at)}; sealing again extends it`}
          >
            {new Date(session.expires_at).toLocaleTimeString(undefined, {
              hour: "numeric",
              minute: "2-digit",
            })}
          </time>
        </p>
      </div>

      {remove.error && (
        <p role="alert" className="px-4 py-3 text-sm text-destructive">
          Could not remove the change: {extractApiError(remove.error)}
        </p>
      )}
      {changes.length === 0 ? (
        <p className="px-4 py-3 text-sm text-muted-foreground">{NOTHING_YET}</p>
      ) : (
        <ul
          aria-label="Pending changes"
          className="max-h-72 divide-y divide-border/60 overflow-y-auto"
        >
          {changes.map((c) => (
            <ChangeItem
              key={c.id}
              change={c}
              removing={remove.isPending && remove.variables?.id === c.id}
              onRemove={() => remove.mutate(c)}
              onSelectFile={() => onSelectFile(c.path)}
            />
          ))}
        </ul>
      )}

      <div className="flex items-center gap-2 border-t border-border px-4 py-3">
        <Button
          size="sm"
          className="flex-1"
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
        <Button
          variant="ghost"
          size="sm"
          className="text-muted-foreground hover:text-destructive"
          onClick={() => setConfirming("discard")}
        >
          Discard
        </Button>
      </div>

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
