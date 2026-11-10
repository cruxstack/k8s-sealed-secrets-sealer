import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Eye, EyeOff, Loader2, Lock } from "lucide-react";
import { extractApiError } from "@/api/client";
import {
  getSeal,
  openSession,
  requestSeal,
  sessionQueryKey,
} from "@/api/queries/sessions";
import type { RepositoryFile, Seal, SealSession } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { cn, shortFingerprint } from "@/lib/utils";

/** How often a seal's progress is checked; tests shorten it. */
export const sealPolling = { intervalMs: 1000 };

const KEY_PATTERN = /^[-._a-zA-Z0-9]+$/;

/** Why a key cannot name a Secret value, or null when it can. */
export function keyProblem(key: string): string | null {
  if (key === "") return null;
  if (
    key.length > 253 ||
    key === "." ||
    key === ".." ||
    !KEY_PATTERN.test(key)
  ) {
    return "Use letters, digits, '-', '_' or '.', at most 253 characters.";
  }
  return null;
}

const DONE = new Set<Seal["status"]>(["sealed", "failed", "expired"]);

function agentName(seal: Seal): string {
  return seal.agent.cluster || seal.agent.id;
}

interface SealFormProps {
  owner: string;
  repo: string;
  file: RepositoryFile;
  /** The commit the page shows; a new session opens there. */
  commit: string;
  session: SealSession | null;
  onClose: () => void;
}

/**
 * Seals one value into every document of a file. The value lives only in
 * this form: it is sent once, kept until the seal succeeds (so a failed seal
 * can be retried) and cleared then.
 */
export function SealForm({
  owner,
  repo,
  file,
  commit,
  session,
  onClose,
}: SealFormProps) {
  const queryClient = useQueryClient();
  const id = useId();
  const keyRef = useRef<HTMLInputElement>(null);
  const alive = useRef(true);
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [shown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [seal, setSeal] = useState<Seal | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    alive.current = true;
    keyRef.current?.focus();
    return () => {
      alive.current = false;
    };
  }, []);

  const docs = file.documents ?? [];
  const problem = keyProblem(key);
  const replaces = key !== "" && docs.some((d) => d.keys.includes(key));
  const canSubmit = !busy && key !== "" && !problem && value !== "";

  async function submit(e?: FormEvent) {
    e?.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    setSeal(null);
    try {
      let current = session;
      if (!current) {
        current = await openSession(owner, repo, commit);
        queryClient.setQueryData(sessionQueryKey(owner, repo), {
          ...current,
          changes: current.changes ?? [],
        });
      }
      let progress = await requestSeal(owner, repo, current.id, {
        path: file.path,
        key,
        value,
      });
      setSeal(progress);
      while (!DONE.has(progress.status)) {
        await new Promise((resolve) =>
          setTimeout(resolve, sealPolling.intervalMs),
        );
        if (!alive.current) return;
        progress = await getSeal(owner, repo, current.id, progress.id);
        if (!alive.current) return;
        setSeal(progress);
      }
      if (progress.status === "sealed") {
        setKey("");
        setValue("");
        setShown(false);
        keyRef.current?.focus();
      }
      void queryClient.invalidateQueries({
        queryKey: sessionQueryKey(owner, repo),
      });
      void queryClient.invalidateQueries({ queryKey: ["sessions"] });
    } catch (err) {
      if (alive.current) setError(extractApiError(err));
    } finally {
      if (alive.current) setBusy(false);
    }
  }

  return (
    <form
      onSubmit={(e) => void submit(e)}
      aria-label={`Seal a value into ${file.path}`}
      className="space-y-4 border-t border-border bg-muted/30 px-4 py-4"
    >
      <p className="text-sm text-muted-foreground">
        {docs.length === 1
          ? "One value, sealed for the document above"
          : `One value, sealed for each of the ${docs.length} documents above`}{" "}
        with the env key. It is encrypted as soon as it reaches the server, and
        only the agent that seals it can read it.
      </p>
      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <div className="space-y-2">
          <Label htmlFor={`${id}-key`}>Key</Label>
          <Input
            ref={keyRef}
            id={`${id}-key`}
            className="font-mono"
            placeholder="e.g. api-token"
            autoComplete="off"
            spellCheck={false}
            value={key}
            disabled={busy}
            aria-invalid={problem ? true : undefined}
            aria-describedby={`${id}-key-help`}
            onChange={(e) => setKey(e.target.value.trim())}
          />
          <p
            id={`${id}-key-help`}
            className={cn(
              "text-xs",
              problem ? "text-destructive" : "text-muted-foreground",
            )}
          >
            {problem ??
              (replaces
                ? `Replaces the existing value of ${key}.`
                : "The name in spec.encryptedData.")}
          </p>
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label htmlFor={`${id}-value`}>Value</Label>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs"
              onClick={() => setShown((s) => !s)}
              aria-pressed={shown}
            >
              {shown ? (
                <EyeOff className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
              ) : (
                <Eye className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
              )}
              {shown ? "Hide" : "Show"}
            </Button>
          </div>
          <Textarea
            id={`${id}-value`}
            rows={3}
            className={cn(
              "font-mono",
              !shown && "[-webkit-text-security:disc]",
            )}
            autoComplete="off"
            spellCheck={false}
            data-1p-ignore
            data-lpignore="true"
            data-form-type="other"
            value={value}
            disabled={busy}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                void submit();
              }
            }}
          />
        </div>
      </div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <SealProgress seal={seal} busy={busy} error={error} />
        <div className="flex shrink-0 gap-2 sm:ml-auto">
          <Button type="button" variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button type="submit" disabled={!canSubmit}>
            {busy ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Lock className="mr-2 h-4 w-4" aria-hidden />
            )}
            Seal
          </Button>
        </div>
      </div>
    </form>
  );
}

function SealProgress({
  seal,
  busy,
  error,
}: {
  seal: Seal | null;
  busy: boolean;
  error: string | null;
}) {
  if (error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {error}
      </p>
    );
  }
  if (!seal) {
    return busy ? (
      <p role="status" className="text-sm text-muted-foreground">
        Sending…
      </p>
    ) : (
      <p className="text-xs text-muted-foreground">
        Press Ctrl+Enter or ⌘+Enter in the value to seal.
      </p>
    );
  }
  switch (seal.status) {
    case "queued":
    case "sealing":
      return (
        <p
          role="status"
          className="flex items-center gap-2 text-sm text-muted-foreground"
        >
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {seal.status === "queued"
            ? `Waiting for ${agentName(seal)}…`
            : `Sealing in ${agentName(seal)}…`}
        </p>
      );
    case "sealed":
      return (
        <p role="status" className="flex items-center gap-2 text-sm">
          <CheckCircle2
            className="h-4 w-4 shrink-0 text-success"
            aria-hidden="true"
          />
          <span>
            Sealed <code className="font-mono text-xs">{seal.key}</code> for{" "}
            {seal.targets.length === 1
              ? "1 document"
              : `${seal.targets.length} documents`}{" "}
            in {agentName(seal)} with{" "}
            <code className="font-mono text-xs" title={seal.fingerprint}>
              {shortFingerprint(seal.fingerprint)}
            </code>
            .
          </span>
        </p>
      );
    default:
      return (
        <p role="alert" className="text-sm text-destructive">
          {seal.status === "expired" ? "Sealing timed out: " : "Not sealed: "}
          {seal.error ?? "try again."}
        </p>
      );
  }
}
