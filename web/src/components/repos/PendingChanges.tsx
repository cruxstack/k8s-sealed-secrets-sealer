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
import { Alert } from "@/components/ui/alert";
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
import { RegionTag } from "@/components/ui/region-tag";
import { RelativeTime } from "@/components/ui/relative-time";
import { CardHeading } from "@/components/ui/section-heading";
import { safeHttpUrl, shortFingerprint } from "@/lib/utils";
import { PathLine } from "./FileList";
import { regionList } from "./keys";

function plural(n: number, one: string, many: string) {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/** A change's key, with the regions it was sealed for when limited. */
function keyIn(c: PendingChange): string {
  return c.regions?.length ? `${c.key} in ${regionList(c.regions)}` : c.key;
}

/** The files a session changes, each with its changes, in order. */
function filesOf(changes: PendingChange[]): [string, PendingChange[]][] {
  const files = new Map<string, PendingChange[]>();
  for (const c of changes) files.set(c.path, [...(files.get(c.path) ?? []), c]);
  return [...files];
}

/** Whether a change is the file's own value, resealed onto the env key. */
function isReseal(c: PendingChange): boolean {
  return c.kind === "reseal";
}

/** "from SHA256:AAAAaaaa…", "… and 1 more": the keys a reseal came off. */
function FromKeys({ change }: { change: PendingChange }) {
  const from = change.resealed_from ?? [];
  if (from.length === 0) return <span>from an older key</span>;
  return (
    <span title={`Resealed from ${from.join(", ")}`}>
      from <code className="font-mono">{shortFingerprint(from[0]!, 8)}</code>
      {from.length > 1 && ` and ${from.length - 1} more`}
    </span>
  );
}

/** A resealed change's marker: the same value, on the env key now. */
function ResealedBadge({ change }: { change: PendingChange }) {
  const from = change.resealed_from ?? [];
  return (
    <Badge
      variant="secondary"
      className="shrink-0"
      title={`The file's own value, resealed onto the env key from ${from.length > 0 ? from.join(", ") : "an older key"}. Resealing doesn't rotate it.`}
    >
      Resealed
    </Badge>
  );
}

/** A change's key in monospace, then its regions as tags. */
function KeyChip({ change }: { change: PendingChange }) {
  return (
    <span className="inline-flex items-center gap-1">
      <code className="rounded-md border border-border bg-card px-1.5 py-0.5 font-mono text-xs">
        {change.key}
      </code>
      {change.regions?.map((r) => (
        <RegionTag key={r} region={r} />
      ))}
      {isReseal(change) && <ResealedBadge change={change} />}
    </span>
  );
}

/** "2 sealed values and 3 resealed values": what a pull request writes. */
function valuesText(changes: PendingChange[]): string {
  // as the pull request's title counts them: a sealed value per change,
  // and a resealed value per document, since each document's was its own
  const resealed = changes
    .filter(isReseal)
    .reduce((n, c) => n + c.targets.length, 0);
  const sealed = changes.filter((c) => !isReseal(c)).length;
  if (resealed === 0) return plural(sealed, "sealed value", "sealed values");
  const moved = plural(resealed, "resealed value", "resealed values");
  return sealed === 0
    ? moved
    : `${plural(sealed, "sealed value", "sealed values")} and ${moved}`;
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
        <p className="flex min-w-0 flex-wrap items-center gap-1.5">
          <code className="truncate font-mono text-[13px] font-medium">
            {change.key}
          </code>
          {change.regions?.map((r) => (
            <RegionTag
              key={r}
              region={r}
              className="shrink-0"
              title={`Sealed for ${r} only`}
            />
          ))}
          {isReseal(change) && <ResealedBadge change={change} />}
          {change.key_revoked && (
            <Badge
              variant="warning"
              className="shrink-0"
              title="Sealed with a key an admin has since revoked. Seal the value again, or remove it, before opening a pull request."
            >
              Seal Again
            </Badge>
          )}
        </p>
        <button
          type="button"
          onClick={onSelectFile}
          className="block max-w-full rounded text-xs hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          title={`Show ${change.path}`}
        >
          <PathLine path={change.path} quiet />
        </button>
        <p className="text-xs text-muted-foreground">
          <span title={targets}>
            {plural(change.targets.length, "document", "documents")}
            {change.regions?.length ? ` in ${regionList(change.regions)}` : ""}
          </span>{" "}
          ·{" "}
          {isReseal(change) && (
            <>
              <FromKeys change={change} /> ·{" "}
            </>
          )}
          <RelativeTime
            iso={change.sealed_at}
            past
            describe={(at) =>
              `${isReseal(change) ? "Resealed" : "Sealed"} by ${agent} with ${change.fingerprint}, ${at}`
            }
          />
        </p>
      </div>
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8 shrink-0 text-muted-foreground hover:text-destructive"
        onClick={onRemove}
        disabled={removing}
        aria-label={`Remove ${keyIn(change)} from ${change.path}`}
        title="Remove This Change"
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
  /** A file is being resealed; its changes are not listed yet. */
  resealing?: boolean;
  onOpened: (pr: PullRequest) => void;
  onSelectFile: (path: string) => void;
}

/**
 * The user's pending changes to a repository, like a cart beside the files:
 * open a pull request with them, remove one, or discard them all. Without a
 * change it says what will gather here.
 */
export function PendingChanges({
  session,
  ...props
}: Omit<ChangesProps, "session"> & { session: SealSession | null }) {
  if (session) return <SessionChanges session={session} {...props} />;
  return (
    <section
      aria-labelledby="pending-heading"
      className="shrink-0 overflow-hidden rounded-xl border bg-card shadow-xs dark:shadow-none"
    >
      <div className="border-b border-border px-4 py-3">
        <CardHeading id="pending-heading" count={0}>
          Pending Changes
        </CardHeading>
      </div>
      <p className="px-4 py-3 text-xs text-muted-foreground">{NOTHING_YET}</p>
    </section>
  );
}

function SessionChanges({
  owner,
  repo,
  session,
  sealing = false,
  resealing = false,
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
      toast.success(
        `Discarded ${plural(changes.length, "pending change", "pending changes")}`,
        {
          description: (
            <code className="font-mono text-xs">{session.repository}</code>
          ),
        },
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
      toast.success(
        <span>
          Removed <code className="font-mono">{change.key}</code>
          {change.regions?.length ? ` in ${regionList(change.regions)}` : ""}
        </span>,
        {
          description: (
            <code className="font-mono text-xs [overflow-wrap:anywhere]">
              {change.path}
            </code>
          ),
        },
      ),
    onSettled: refresh,
  });
  const openBlocked = sealing
    ? "Wait for the seal in progress to finish."
    : resealing
      ? "Wait for the reseal in progress to finish."
      : changes.some((c) => c.key_revoked)
        ? "Seal again, or remove, the values sealed with a revoked key."
        : null;

  return (
    <section
      aria-labelledby="pending-heading"
      className="shrink-0 overflow-hidden rounded-xl border bg-card shadow-xs dark:shadow-none"
    >
      <div className="space-y-0.5 border-b border-border px-4 py-3">
        <CardHeading id="pending-heading" count={changes.length}>
          Pending Changes
        </CardHeading>
        <p className="text-xs text-muted-foreground">
          On <code className="font-mono">{session.branch}</code> at{" "}
          <code className="font-mono" title={session.commit}>
            {session.commit.slice(0, 7)}
          </code>{" "}
          · expires{" "}
          <RelativeTime
            iso={session.expires_at}
            describe={(at) => `${at}; sealing again extends it`}
          />
        </p>
      </div>

      {remove.error && (
        <div className="px-4 pt-3">
          <Alert variant="destructive" role="alert">
            Could not remove the change: {extractApiError(remove.error)}
          </Alert>
        </div>
      )}
      {changes.length === 0 ? (
        <p className="px-4 py-3 text-xs text-muted-foreground">{NOTHING_YET}</p>
      ) : (
        <>
          <ul
            aria-label="Pending changes"
            className="max-h-72 divide-y divide-border overflow-y-auto"
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

          <div className="space-y-2 border-t border-border px-4 py-3">
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                className="flex-1"
                disabled={openBlocked !== null}
                title={openBlocked ?? undefined}
                aria-describedby={
                  openBlocked ? "open-pull-request-blocked" : undefined
                }
                onClick={() => {
                  open.reset();
                  setConfirming("open");
                }}
              >
                <GitPullRequest className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Open Pull Request
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
            {openBlocked && (
              <p
                id="open-pull-request-blocked"
                className="text-xs text-muted-foreground"
              >
                {openBlocked}
              </p>
            )}
          </div>
        </>
      )}

      <Dialog
        open={confirming === "open"}
        onOpenChange={(o) =>
          !open.isPending && setConfirming(o ? "open" : null)
        }
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Open a Pull Request?</DialogTitle>
            <DialogDescription>
              One commit on a new branch from{" "}
              <code className="font-mono">{session.branch}</code> at{" "}
              <code className="font-mono">{session.commit.slice(0, 7)}</code>{" "}
              writes {valuesText(changes)} into{" "}
              {plural(files.length, "file", "files")}, changing only{" "}
              <code className="font-mono">spec.encryptedData</code>. The GitHub
              App opens the pull request into{" "}
              <code className="font-mono">{session.branch}</code> and names you
              as its requester; your pending changes are then cleared.
            </DialogDescription>
          </DialogHeader>
          <ul
            aria-label="Files in the pull request"
            className="max-h-48 space-y-3 overflow-y-auto rounded-lg border border-border bg-muted/40 p-3 text-sm"
          >
            {files.map(([path, mine]) => (
              <li key={path} className="space-y-1.5">
                <div
                  className="truncate font-mono text-xs font-medium"
                  title={path}
                >
                  {path}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {mine.map((c) => (
                    <KeyChip key={c.id} change={c} />
                  ))}
                </div>
              </li>
            ))}
          </ul>
          {open.error && (
            <Alert variant="destructive" role="alert">
              Could not open the pull request: {extractApiError(open.error)}
            </Alert>
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
              {open.isPending ? "Opening…" : "Open Pull Request"}
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
            <DialogTitle>Discard Pending Changes?</DialogTitle>
            <DialogDescription>
              This removes{" "}
              {plural(changes.length, "pending change", "pending changes")} to{" "}
              <code className="font-mono">{session.repository}</code>. Nothing
              was committed, so nothing changes on GitHub.
            </DialogDescription>
          </DialogHeader>
          {discard.error && (
            <Alert variant="destructive" role="alert">
              Could not discard: {extractApiError(discard.error)}
            </Alert>
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
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-success-subtle">
              <CheckCircle2
                className="h-8 w-8 text-success"
                aria-hidden="true"
              />
            </div>
            <DialogHeader className="space-y-2 pr-0 text-center">
              <DialogTitle className="text-xl">
                Pull Request #{pr.number} Is Open
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
            {/* the way forward and the way back, the same size */}
            <div className="flex flex-col gap-2 pt-2">
              {url && (
                <Button asChild className="w-full">
                  <a href={url} target="_blank" rel="noopener noreferrer">
                    View Pull Request
                    <ExternalLink className="ml-2 h-4 w-4" aria-hidden="true" />
                  </a>
                </Button>
              )}
              <Button variant="outline" className="w-full" onClick={onClose}>
                Keep Sealing
              </Button>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
