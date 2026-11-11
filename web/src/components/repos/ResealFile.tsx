import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, RotateCcwKey } from "lucide-react";
import { toast } from "sonner";
import { extractApiError } from "@/api/client";
import {
  getReseal,
  openSession,
  requestReseal,
  sessionQueryKey,
} from "@/api/queries/sessions";
import type {
  FileReseal,
  RepositoryFile,
  SealSession,
  SealingStatus,
} from "@/api/types";
import { Point, Points } from "@/components/fleet/KeyDialogs";
import { plural } from "@/components/fleet/references";
import { resealBlocked } from "@/components/reseal/format";
import { Progress } from "@/components/reseal/status";
import { Alert } from "@/components/ui/alert";
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
import { ReasonButton } from "@/components/ui/reason-button";
import { RegionTag } from "@/components/ui/region-tag";
import { sentence } from "@/lib/utils";
import { isPending, pendingDocs } from "./keys";

/** How often a file reseal's progress is checked; tests shorten it. */
export const resealPolling = { intervalMs: 1000 };

const FINISHED = new Set<FileReseal["status"]>(["done", "failed", "expired"]);

/** Where "Reseal all" stands in a repository's workspace. */
export interface FileResealState {
  /** The file resealed, or about to be; null before any. */
  path: string | null;
  /** `confirm`: asking; `running`: resealing; `done`: its summary. */
  phase: "confirm" | "running" | "done";
  progress: FileReseal | null;
  /** Why the reseal could not start or finish. */
  error: string | null;
  /** Whether its dialog shows. */
  open: boolean;
}

const IDLE: FileResealState = {
  path: null,
  phase: "confirm",
  progress: null,
  error: null,
  open: false,
};

export interface FileResealer {
  state: FileResealState;
  /** Opens the dialog for a file: its progress while it runs, or asks. */
  ask: (path: string) => void;
  close: () => void;
  start: (session: SealSession | null, commit: string) => void;
}

/**
 * "Reseal all" for a repository's workspace: one file at a time, which
 * keeps running while another file is shown. The state lives with the
 * workspace, so picking another file neither stops it nor loses its
 * summary; one that finishes with its dialog closed says so in a toast.
 */
export function useFileReseal(owner: string, repo: string): FileResealer {
  const queryClient = useQueryClient();
  const [state, setState] = useState<FileResealState>(IDLE);
  const alive = useRef(true);
  const open = useRef(false);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    open.current = state.open;
  }, [state.open]);
  const update = useCallback((patch: Partial<FileResealState>) => {
    if (alive.current) setState((s) => ({ ...s, ...patch }));
  }, []);

  const ask = useCallback((path: string) => {
    setState((s) =>
      s.phase === "running"
        ? { ...s, open: s.path === path }
        : { ...IDLE, path, open: true },
    );
  }, []);
  const close = useCallback(() => {
    setState((s) => ({ ...s, open: false }));
  }, []);

  const start = useCallback(
    (session: SealSession | null, commit: string) => {
      const path = state.path;
      if (!path || state.phase === "running") return;
      update({ phase: "running", progress: null, error: null });
      void (async () => {
        try {
          let current = session;
          if (!current) {
            // the first change opens a session where the page is, as a
            // seal does
            current = await openSession(owner, repo, commit);
            queryClient.setQueryData(sessionQueryKey(owner, repo), {
              ...current,
              changes: current.changes ?? [],
            });
          }
          let progress = await requestReseal(owner, repo, current.id, path);
          update({ progress });
          while (!FINISHED.has(progress.status)) {
            await new Promise((resolve) =>
              setTimeout(resolve, resealPolling.intervalMs),
            );
            if (!alive.current) return;
            progress = await getReseal(owner, repo, current.id, progress.id);
            update({ progress });
          }
          update({ phase: "done" });
          void queryClient.invalidateQueries({
            queryKey: sessionQueryKey(owner, repo),
          });
          void queryClient.invalidateQueries({ queryKey: ["sessions"] });
          if (!open.current && alive.current) {
            const { title, tone } = summaryTitle(progress);
            toast[tone](title, {
              description: (
                <code className="font-mono text-xs [overflow-wrap:anywhere]">
                  {path}
                </code>
              ),
            });
          }
        } catch (err) {
          // back to asking, with why, where it can be tried again
          update({ phase: "confirm", error: extractApiError(err), open: true });
        }
      })();
    },
    [owner, repo, queryClient, state.path, state.phase, update],
  );

  return { state, ask, close, start };
}

/** What a finished reseal did, in a few words. */
function summaryTitle(r: FileReseal): {
  title: string;
  tone: "success" | "error";
} {
  if (r.status === "expired") {
    return { title: "Resealing timed out", tone: "error" };
  }
  if (r.status === "failed")
    return { title: "Resealing failed", tone: "error" };
  const { resealed, failed } = r.values;
  if (resealed > 0) {
    return { title: `Resealed ${plural(resealed, "value")}`, tone: "success" };
  }
  if (failed > 0) return { title: "No value was resealed", tone: "error" };
  return { title: "Nothing to reseal", tone: "success" };
}

/** The values of a file's documents for the env, and those pending. */
function fileValues(file: RepositoryFile, session: SealSession | null) {
  const docs = file.documents ?? [];
  const pending = pendingDocs(session?.changes ?? [], file.path);
  let total = 0;
  let waiting = 0;
  for (const d of docs) {
    for (const key of d.keys) {
      total++;
      if (isPending(pending, key, d)) waiting++;
    }
  }
  return { docs: docs.length, total, waiting };
}

/** Why "Reseal all" cannot be used on a file now, or undefined. */
export function resealAllReason({
  file,
  env,
  canWrite,
  sealing,
  status,
  values,
}: {
  file: RepositoryFile;
  env: string;
  canWrite: boolean;
  sealing: boolean;
  status: SealingStatus | undefined;
  values: number;
}): string | undefined {
  if (!canWrite) {
    return "Resealing needs write access to this repository on GitHub.";
  }
  if (!status) return "Checking whether values can be resealed…";
  const blocked = resealBlocked(status);
  if (blocked) return blocked;
  if ((file.documents ?? []).length === 0) {
    return `This file has no SealedSecret for the ${env} env.`;
  }
  if (values === 0) return `This file has no sealed values for the ${env} env.`;
  if (sealing) return "Wait for the seal in progress to finish.";
  return undefined;
}

/** What resealing the file will and won't do, before it starts. */
function ConfirmStep({
  file,
  env,
  values,
  error,
  onConfirm,
}: {
  file: RepositoryFile;
  env: string;
  values: ReturnType<typeof fileValues>;
  error: string | null;
  onConfirm: () => void;
}) {
  return (
    <>
      <DialogHeader>
        <DialogTitle>Reseal all values in this file?</DialogTitle>
        <DialogDescription>
          <code className="font-mono text-xs [overflow-wrap:anywhere]">
            {file.path}
          </code>{" "}
          holds {plural(values.total, "value")} in{" "}
          {plural(values.docs, "document")} for the{" "}
          <span className="font-medium text-foreground">{env}</span> env.
        </DialogDescription>
      </DialogHeader>
      <Points>
        <Point lead="Values on older keys move to the env key.">
          Each one sealed with an older key is re-encrypted for the env key, for
          the same namespace, name and scope.
        </Point>
        <Point lead="They become pending changes.">
          Open a pull request with them, as with any seal.
        </Point>
        <Point>
          {values.waiting > 0
            ? `${plural(values.waiting, "value has a pending change", "values have pending changes")} in your session, so ${values.waiting === 1 ? "it is" : "they are"} left alone.`
            : "Values with a pending change in your session are left alone."}
        </Point>
        <Point>Values already on the env key don't change.</Point>
        <Point lead="It doesn't rotate values.">
          Git history keeps the old ciphertext, so a value sealed with a key
          that may be exposed still needs a new value: seal one instead.
        </Point>
      </Points>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          Could not reseal the file: {sentence(error)}
        </p>
      )}
      <DialogFooter>
        <DialogClose asChild>
          <Button variant="outline">Cancel</Button>
        </DialogClose>
        <Button onClick={onConfirm}>
          <RotateCcwKey className="mr-2 h-4 w-4" aria-hidden="true" />
          Reseal all
        </Button>
      </DialogFooter>
    </>
  );
}

/** The agent's name, as people know it. */
function agentName(r: FileReseal | null): string | null {
  return r?.agent ? r.agent.cluster || r.agent.id : null;
}

/** How far the reseal has got. */
function RunningStep({ progress }: { progress: FileReseal | null }) {
  const agent = agentName(progress);
  const v = progress?.values;
  const todo = v ? v.total - v.pending : 0;
  const done = v ? v.resealed + v.current + v.failed : 0;
  return (
    <>
      <DialogHeader>
        <DialogTitle>Resealing…</DialogTitle>
        <DialogDescription>
          <code className="font-mono text-xs [overflow-wrap:anywhere]">
            {progress?.path}
          </code>
        </DialogDescription>
      </DialogHeader>
      <div className="space-y-2">
        <p role="status" className="flex items-center gap-2 text-sm">
          <Loader2
            className="h-4 w-4 shrink-0 animate-spin text-muted-foreground"
            aria-hidden="true"
          />
          {!progress
            ? "Sending…"
            : progress.status === "queued"
              ? agent
                ? `Waiting for ${agent}…`
                : "Waiting for an agent…"
              : `Resealing in ${agent ?? "an agent"}: ${done} of ${plural(todo, "value")}…`}
        </p>
        {progress && todo > 0 && (
          <Progress done={done} total={todo} label="Values checked" />
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        You can close this. The resealed values join your pending changes when
        it finishes.
      </p>
      <DialogFooter>
        <DialogClose asChild>
          {/* the button that started it is gone: focus stays in the dialog */}
          <Button variant="outline" autoFocus>
            Close
          </Button>
        </DialogClose>
      </DialogFooter>
    </>
  );
}

/** What the reseal did: resealed, current, failed with why, left out. */
function DoneStep({ progress }: { progress: FileReseal }) {
  const { title } = summaryTitle(progress);
  const v = progress.values;
  const failures = progress.failures ?? [];
  return (
    <>
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>
          <code className="font-mono text-xs [overflow-wrap:anywhere]">
            {progress.path}
          </code>
        </DialogDescription>
      </DialogHeader>
      {progress.error && (
        <Alert variant="destructive" role="alert">
          {sentence(progress.error)}
        </Alert>
      )}
      <ul aria-label="Reseal summary" className="space-y-1.5 text-sm">
        <li className="flex items-start gap-2">
          <CheckCircle2
            className="mt-0.5 h-4 w-4 shrink-0 text-success"
            aria-hidden="true"
          />
          <span>
            <span className="font-medium">{v.resealed} resealed</span>
            {v.resealed > 0 && (
              <span className="text-muted-foreground">
                , now in your pending changes
              </span>
            )}
          </span>
        </li>
        <li className="pl-6 text-muted-foreground">
          {v.current} already on the env key
        </li>
        {v.failed > 0 && (
          <li className="pl-6 text-destructive">{v.failed} failed</li>
        )}
        {v.pending > 0 && (
          <li className="pl-6 text-muted-foreground">
            {v.pending} left out: {v.pending === 1 ? "it has" : "they have"} a
            pending change
          </li>
        )}
      </ul>
      {failures.length > 0 && (
        <ul
          aria-label="Values that could not be resealed"
          className="max-h-48 space-y-1.5 overflow-y-auto rounded-lg border border-border bg-muted/40 p-3 text-sm"
        >
          {failures.map((f, i) => (
            <li key={`${f.key}:${f.document}:${i}`} className="space-y-0.5">
              <p className="flex flex-wrap items-center gap-1.5">
                <code className="font-mono text-xs font-medium">{f.key}</code>
                <span className="text-xs text-muted-foreground">
                  document #{f.document}
                </span>
                {f.region && <RegionTag region={f.region} />}
              </p>
              <p className="text-xs text-destructive">{sentence(f.error)}</p>
            </li>
          ))}
        </ul>
      )}
      <DialogFooter>
        <DialogClose asChild>
          <Button autoFocus>Done</Button>
        </DialogClose>
      </DialogFooter>
    </>
  );
}

/**
 * "Reseal all" in a file's header, for the env's admins: every value of
 * the file's documents on an older key moves to the env key, as pending
 * changes. It is grayed out, with the reason, when it cannot be used.
 */
export function ResealAll({
  file,
  env,
  session,
  commit,
  canWrite,
  sealing,
  status,
  resealer,
}: {
  file: RepositoryFile;
  env: string;
  session: SealSession | null;
  /** The commit the page shows; a new session opens there. */
  commit: string;
  canWrite: boolean;
  /** A seal is in progress on the page. */
  sealing: boolean;
  status: SealingStatus | undefined;
  resealer: FileResealer;
}) {
  const { state } = resealer;
  const here = state.path === file.path;
  const running = state.phase === "running";
  const values = fileValues(file, session);
  const reason =
    running && !here
      ? `A reseal of ${state.path} is running. Wait for it to finish.`
      : running
        ? undefined
        : resealAllReason({
            file,
            env,
            canWrite,
            sealing,
            status,
            values: values.total,
          });
  return (
    <>
      <ReasonButton
        variant="outline"
        size="sm"
        className="min-w-28"
        reason={reason}
        onClick={() => resealer.ask(file.path)}
      >
        {running && here ? (
          <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />
        ) : (
          <RotateCcwKey className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
        )}
        {running && here ? "Resealing…" : "Reseal all"}
      </ReasonButton>
      <Dialog
        open={state.open && here}
        onOpenChange={(o) => !o && resealer.close()}
      >
        <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto">
          {state.phase === "confirm" && (
            <ConfirmStep
              file={file}
              env={env}
              values={values}
              error={state.error}
              onConfirm={() => resealer.start(session, commit)}
            />
          )}
          {state.phase === "running" && (
            <RunningStep progress={state.progress} />
          )}
          {state.phase === "done" && state.progress && (
            <DoneStep progress={state.progress} />
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
