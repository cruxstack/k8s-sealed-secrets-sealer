import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Check, CheckCircle2, Eye, EyeOff, Loader2, Lock } from "lucide-react";
import { toast } from "sonner";
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
import { Kbd } from "@/components/ui/kbd";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { modKey } from "@/lib/shortcuts";
import { cn, shortFingerprint } from "@/lib/utils";
import { fileHints, missingKeys } from "./hints";

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

function documents(n: number): string {
  return n === 1 ? "1 document" : `${n} documents`;
}

interface SealFormProps {
  owner: string;
  repo: string;
  file: RepositoryFile;
  /** The commit the page shows; a new session opens there. */
  commit: string;
  session: SealSession | null;
  /** Keys of this file with a value waiting in the session. */
  pendingKeys: Set<string>;
  /** Told when a seal starts and ends, and that none runs on unmount. */
  onBusyChange?: (busy: boolean) => void;
  /** Focus the key on mount, when the user just picked this file. */
  autoFocus?: boolean;
}

/**
 * Seals one value into every document of a file, from the keyboard: Enter
 * in the key moves to the value, and ⌘/Ctrl+Enter seals. The value lives
 * only in this form: it is sent once, kept until the seal succeeds (so a
 * failed seal can be retried) and cleared then.
 */
export function SealForm({
  owner,
  repo,
  file,
  commit,
  session,
  pendingKeys,
  onBusyChange,
  autoFocus = false,
}: SealFormProps) {
  const queryClient = useQueryClient();
  const id = useId();
  const keyRef = useRef<HTMLInputElement>(null);
  const valueRef = useRef<HTMLTextAreaElement>(null);
  const alive = useRef(true);
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [shown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [justSealed, setJustSealed] = useState(false);
  // the key takes focus for the next value once the form is enabled again
  const refocus = useRef(false);
  const [seal, setSeal] = useState<Seal | null>(null);
  const [error, setError] = useState<string | null>(null);

  // the form is keyed by file: autoFocus matters only when it mounts
  const focusOnMount = useRef(autoFocus);
  useEffect(() => {
    alive.current = true;
    if (focusOnMount.current) keyRef.current?.focus();
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    onBusyChange?.(busy);
  }, [busy, onBusyChange]);
  useEffect(() => () => onBusyChange?.(false), [onBusyChange]);
  useEffect(() => {
    if (!busy && refocus.current) {
      refocus.current = false;
      keyRef.current?.focus();
    }
  }, [busy]);
  useEffect(() => {
    if (!justSealed) return;
    const t = window.setTimeout(() => setJustSealed(false), 2000);
    return () => window.clearTimeout(t);
  }, [justSealed]);

  const docs = file.documents ?? [];
  const existing = [...new Set(docs.flatMap((d) => d.keys))];
  const { expected } = fileHints(file);
  // the keys the file expects first, then the rest it holds
  const suggestions = [
    ...new Set([
      ...expected,
      ...[...new Set([...existing, ...pendingKeys])].sort(),
    ]),
  ];
  const problem = keyProblem(key);
  // a new key the file does not expect is likely a typo
  const unexpected =
    !problem &&
    key !== "" &&
    expected.length > 0 &&
    !expected.includes(key) &&
    !existing.includes(key) &&
    !pendingKeys.has(key);
  const canSubmit = !busy && key !== "" && !problem && value !== "";
  const note = problem
    ? problem
    : pendingKeys.has(key)
      ? `Replaces the value of ${key} you sealed in this session.`
      : existing.includes(key)
        ? `Replaces the current value of ${key} in the file.`
        : unexpected
          ? `Adds ${key} to spec.encryptedData, but this file does not expect it. Check the name.`
          : key
            ? `Adds ${key} to spec.encryptedData.`
            : expected.length > 0
              ? "The name in spec.encryptedData; pick an expected key or type one."
              : "The name in spec.encryptedData; existing keys are suggested.";
  const pick = (k: string) => {
    setKey(k);
    valueRef.current?.focus();
  };

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
        toast.success(`Sealed ${progress.key}`, {
          description: `For ${documents(progress.targets.length)} in ${agentName(progress)}, with ${shortFingerprint(progress.fingerprint)}`,
        });
        setKey("");
        setValue("");
        setShown(false);
        setJustSealed(true);
        refocus.current = true;
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

  const onSubmitKeys = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void submit();
    }
  };

  return (
    <form
      onSubmit={(e) => void submit(e)}
      aria-label={`Seal a value into ${file.path}`}
      className="space-y-4 border-t border-border bg-muted/25 px-5 py-5"
    >
      <div className="flex items-baseline justify-between gap-4">
        <h3 className="text-sm font-semibold">Seal a value</h3>
        <p className="text-xs text-muted-foreground">
          {docs.length === 1
            ? "Sealed for the document above"
            : `Sealed once for each of the ${docs.length} documents above`}
        </p>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${id}-key`}>Key</Label>
        <Input
          ref={keyRef}
          id={`${id}-key`}
          list={`${id}-keys`}
          className="h-10 font-mono placeholder:font-sans [&::-webkit-calendar-picker-indicator]:hidden!"
          placeholder="e.g. api-token"
          autoComplete="off"
          spellCheck={false}
          value={key}
          disabled={busy}
          aria-invalid={problem ? true : undefined}
          aria-describedby={`${id}-key-help`}
          onChange={(e) => setKey(e.target.value.trim())}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !(e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              if (key && !problem) valueRef.current?.focus();
              return;
            }
            onSubmitKeys(e);
          }}
        />
        <datalist id={`${id}-keys`}>
          {suggestions.map((k) => (
            <option key={k} value={k} />
          ))}
        </datalist>
        <p
          id={`${id}-key-help`}
          className={cn(
            "text-xs",
            problem
              ? "text-destructive"
              : unexpected
                ? "text-warning"
                : "text-muted-foreground",
          )}
        >
          {note}
        </p>
        {expected.length > 0 && (
          <ExpectedKeys
            expected={expected}
            file={file}
            pendingKeys={pendingKeys}
            current={key}
            disabled={busy}
            onPick={pick}
          />
        )}
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${id}-value`}>Value</Label>
        <div className="relative">
          <Textarea
            ref={valueRef}
            id={`${id}-value`}
            rows={4}
            className={cn(
              "min-h-24 resize-y pr-20 font-mono placeholder:font-sans",
              !shown && "[-webkit-text-security:disc]",
            )}
            placeholder="The value to seal; several lines are fine"
            autoComplete="off"
            spellCheck={false}
            data-1p-ignore
            data-lpignore="true"
            data-form-type="other"
            value={value}
            disabled={busy}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={onSubmitKeys}
          />
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="absolute top-1.5 right-1.5 h-7 px-2 text-xs text-muted-foreground"
            onClick={() => setShown((s) => !s)}
            aria-pressed={shown}
            aria-label={shown ? "Hide the value" : "Show the value"}
          >
            {shown ? (
              <EyeOff className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <Eye className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            )}
            {shown ? "Hide" : "Show"}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Encrypted as soon as it reaches the server; only the agent that seals
          it can read it.
        </p>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <SealProgress seal={seal} busy={busy} error={error} />
        <div className="flex shrink-0 items-center gap-3 sm:ml-auto">
          <span className="hidden items-center gap-1 text-xs text-muted-foreground md:flex">
            <Kbd>{modKey()}</Kbd>
            <Kbd>↵</Kbd>
          </span>
          <Button
            type="submit"
            disabled={!canSubmit}
            className={cn(
              "min-w-28",
              justSealed &&
                "bg-success text-white hover:bg-success/90 disabled:opacity-100",
            )}
          >
            {busy ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
            ) : justSealed ? (
              <Check className="mr-2 h-4 w-4" aria-hidden />
            ) : (
              <Lock className="mr-2 h-4 w-4" aria-hidden />
            )}
            {busy ? "Sealing…" : justSealed ? "Sealed" : "Seal"}
          </Button>
        </div>
      </div>
    </form>
  );
}

/**
 * The keys the file expects, as chips to fill the key with: missing ones
 * dashed, ones with a value waiting in the session marked, and set ones
 * plain.
 */
function ExpectedKeys({
  expected,
  file,
  pendingKeys,
  current,
  disabled,
  onPick,
}: {
  expected: string[];
  file: RepositoryFile;
  pendingKeys: Set<string>;
  current: string;
  disabled: boolean;
  onPick: (key: string) => void;
}) {
  const lacking = new Set(missingKeys(file, pendingKeys));
  const state = (k: string) =>
    pendingKeys.has(k) ? "pending" : lacking.has(k) ? "missing" : "set";
  const missing = lacking.size;
  return (
    <div className="flex flex-wrap items-center gap-1.5 pt-1">
      <span className="mr-0.5 text-xs text-muted-foreground">
        Expected
        {missing > 0 && (
          <span className="text-warning"> · {missing} missing</span>
        )}
      </span>
      <ul className="flex flex-wrap gap-1.5" aria-label="Expected keys">
        {expected.map((k) => {
          const s = state(k);
          return (
            <li key={k}>
              <button
                type="button"
                disabled={disabled}
                onClick={() => onPick(k)}
                aria-pressed={current === k}
                aria-label={`${k}, ${s}`}
                className={cn(
                  "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-xs transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50",
                  s === "missing" &&
                    "border-dashed border-warning/60 text-warning hover:bg-warning/10",
                  s === "pending" &&
                    "border-primary/30 bg-primary/10 text-primary hover:bg-primary/15 dark:bg-primary/20",
                  s === "set" &&
                    "border-border bg-background text-muted-foreground hover:bg-muted hover:text-foreground",
                  current === k && "ring-2 ring-ring/50",
                )}
              >
                {s === "set" && (
                  <Check className="h-3 w-3 text-success" aria-hidden="true" />
                )}
                {k}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
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
      <span />
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
            {documents(seal.targets.length)} in {agentName(seal)} with{" "}
            <code className="font-mono text-xs" title={seal.fingerprint}>
              {shortFingerprint(seal.fingerprint)}
            </code>
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
