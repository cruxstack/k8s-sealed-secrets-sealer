import {
  useEffect,
  useId,
  useImperativeHandle,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
  type Ref,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Check, CheckCircle2, Eye, EyeOff, Loader2, Lock } from "lucide-react";
import { extractApiError } from "@/api/client";
import {
  getSeal,
  openSession,
  requestSeal,
  sessionQueryKey,
} from "@/api/queries/sessions";
import type {
  PendingChange,
  RepositoryFile,
  Seal,
  SealSession,
} from "@/api/types";
import { Button } from "@/components/ui/button";
import { FieldLabel } from "@/components/ui/field-label";
import { InfoTip } from "@/components/ui/info-tip";
import { Input } from "@/components/ui/input";
import { Kbd } from "@/components/ui/kbd";
import { RegionTag } from "@/components/ui/region-tag";
import { Textarea } from "@/components/ui/textarea";
import { useRememberSeal } from "@/lib/recent-repos";
import { modKey } from "@/lib/shortcuts";
import { cn, shortFingerprint } from "@/lib/utils";
import { fileHints } from "./hints";
import {
  fileRegions,
  isPending,
  regionChoices,
  regionList,
  sharesRegions,
  type PendingDocs,
} from "./keys";

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

const DONE = new Set<Seal["status"]>([
  "sealed",
  "superseded",
  "failed",
  "expired",
]);

function agentName(seal: Seal): string {
  return seal.agent.cluster || seal.agent.id;
}

function documents(n: number): string {
  return n === 1 ? "1 document" : `${n} documents`;
}

/** Whether a pending change is the one a seal made. */
function madeBy(c: PendingChange, seal: Seal): boolean {
  const regions = (r?: string[]) => [...(r ?? [])].sort().join(",");
  return (
    c.path === seal.path &&
    c.key === seal.key &&
    regions(c.regions) === regions(seal.regions)
  );
}

/** What the rest of the panel may do with the form. */
export interface SealFormHandle {
  /**
   * Fill the key and move to the value; with regions, limit the seal to
   * them too.
   */
  pick: (key: string, regions?: string[]) => void;
}

interface SealFormProps {
  ref?: Ref<SealFormHandle>;
  owner: string;
  repo: string;
  /** The env the page seals for ("dev"), named in a seal's result. */
  env: string;
  file: RepositoryFile;
  /** The commit the page shows; a new session opens there. */
  commit: string;
  session: SealSession | null;
  /** This file's documents with a value waiting in the session, per key. */
  pending: PendingDocs;
  /** Told when a seal starts and ends, and that none runs on unmount. */
  onBusyChange?: (busy: boolean) => void;
  /** Focus the key on mount, when the user just picked this file. */
  autoFocus?: boolean;
  /** Told the key as it changes, from "" on mount. */
  onKeyChange?: (key: string) => void;
  /**
   * Told the regions the seal is limited to as they change, or null for
   * every document, from null on mount.
   */
  onRegionsChange?: (regions: string[] | null) => void;
}

/**
 * Seals one value into the documents of a file, from the keyboard: Enter
 * in the key moves to the value, and ⌘/Ctrl+Enter seals. When the file's
 * documents are in more than one region, the seal can be limited to some
 * of them, for a value that differs by region. The value lives only in this
 * form: it is sent once, kept until the seal succeeds (so a failed seal can
 * be retried) and cleared then.
 */
export function SealForm({
  ref,
  owner,
  repo,
  env,
  file,
  commit,
  session,
  pending,
  onBusyChange,
  autoFocus = false,
  onKeyChange,
  onRegionsChange,
}: SealFormProps) {
  const queryClient = useQueryClient();
  const remember = useRememberSeal();
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
  // a seal's "Sealed …" line lasts as long as its change: once the change has
  // shown up in the session and then left it (removed, discarded, or sent in
  // a pull request), the line goes too
  const [seenChange, setSeenChange] = useState<string | null>(null);
  if (seal?.status === "sealed") {
    const listed = (session?.changes ?? []).some((c) => madeBy(c, seal));
    if (listed && seenChange !== seal.id) {
      setSeenChange(seal.id);
    } else if (!listed && seenChange === seal.id) {
      setSeenChange(null);
      setSeal(null);
    }
  }
  // the regions to choose between, and those chosen: all of them at first
  const choices = regionChoices(file);
  // the regions the file's documents are for, shown when there is no choice
  const listed = fileRegions(file).filter((r) => r !== "");
  const [chosen, setChosen] = useState<string[]>(choices);
  const everywhere = chosen.length === choices.length;

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
    onKeyChange?.(key);
  }, [key, onKeyChange]);
  const limitedTo = everywhere ? null : chosen.join("\n");
  useEffect(() => {
    onRegionsChange?.(limitedTo === null ? null : limitedTo.split("\n"));
  }, [limitedTo, onRegionsChange]);
  useImperativeHandle(ref, () => ({
    pick: (k: string, regions?: string[]) => {
      setKey(k);
      if (regions) {
        const known = choices.filter((r) => regions.includes(r));
        if (known.length > 0) setChosen(known);
      }
      valueRef.current?.focus();
    },
  }));
  useEffect(() => {
    if (!justSealed) return;
    const t = window.setTimeout(() => setJustSealed(false), 2000);
    return () => window.clearTimeout(t);
  }, [justSealed]);

  const docs = file.documents ?? [];
  // the documents this seal is for
  const targets = everywhere
    ? docs
    : docs.filter(
        (d) =>
          (d.regions ?? []).length > 0 &&
          (d.regions ?? []).every((r) => chosen.includes(r)),
      );
  const unlabelled = docs.some((d) => !d.regions?.length);
  const existing = [...new Set(docs.flatMap((d) => d.keys))];
  const { expected } = fileHints(file);
  // the keys the file expects first, then the rest it holds
  const suggestions = [
    ...new Set([
      ...expected,
      ...[...new Set([...existing, ...pending.keys()])].sort(),
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
    !pending.has(key);
  const pendingHere = targets.some((d) => isPending(pending, key, d));
  const held = targets.filter((d) => d.keys.includes(key)).length;
  const where = everywhere ? "" : ` in ${regionList(chosen)}`;
  const canSubmit = !busy && key !== "" && !problem && value !== "";
  const k = <code className="font-mono">{key}</code>;
  const data = <code className="font-mono">spec.encryptedData</code>;
  // what sealing this key would do, once there is one
  const note: ReactNode = problem ? (
    problem
  ) : pendingHere ? (
    <>
      Replaces the value of {k} you sealed in this session{where}.
    </>
  ) : held === targets.length && held > 0 ? (
    <>
      Replaces the current value of {k}
      {everywhere ? " in the file" : where}.
    </>
  ) : held > 0 ? (
    <>
      Replaces {k} where it is set{where} and adds it to the other documents.
    </>
  ) : unexpected ? (
    <>
      Adds {k} to {data}, but this file does not expect it. Check the name.
    </>
  ) : key ? (
    <>
      Adds {k} to {data}
      {where}.
    </>
  ) : null;
  const toggle = (r: string) =>
    setChosen((c) =>
      c.includes(r)
        ? // at least one region stays chosen
          c.length === 1
          ? c
          : c.filter((x) => x !== r)
        : choices.filter((x) => x === r || c.includes(x)),
    );

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
        regions: everywhere ? undefined : chosen,
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
        // the Secrets page lists the repositories sealed into lately first
        remember(`${owner}/${repo}`, file.path);
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
      className="space-y-4 border-t border-border bg-muted/25 p-4"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="text-sm font-semibold">Seal a Value</h3>
        <p className="text-xs text-muted-foreground">
          {targets.length === 1
            ? `Sealed for the document${where} below`
            : everywhere
              ? `Sealed once for each of the ${docs.length} documents below`
              : `Sealed for the ${targets.length} documents${where} below`}
        </p>
      </div>

      <div className="space-y-2">
        <FieldLabel
          htmlFor={`${id}-key`}
          helpId={`${id}-key-help`}
          help={
            <>
              The value's name in {data}.{" "}
              {expected.length > 0
                ? "Pick a key above or type one."
                : "The file's keys are suggested as you type."}
            </>
          }
        >
          Key
        </FieldLabel>
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
          aria-describedby={
            note ? `${id}-key-note ${id}-key-help` : `${id}-key-help`
          }
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
        {note && (
          <p
            id={`${id}-key-note`}
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
        )}
      </div>

      {choices.length > 1 && (
        <div className="space-y-2">
          <FieldLabel
            id={`${id}-regions`}
            helpId={`${id}-regions-help`}
            help={
              everywhere
                ? "Every document gets the value. For a value that differs by region, choose the regions it is for."
                : `Only the documents in ${regionList(chosen)} get the value${unlabelled ? "; documents without a region are left out" : ""}.`
            }
          >
            Regions
          </FieldLabel>
          <div
            role="group"
            aria-labelledby={`${id}-regions`}
            aria-describedby={`${id}-regions-help`}
            className="flex flex-wrap items-center gap-1.5"
          >
            {choices.map((r) => {
              const on = chosen.includes(r);
              const n = docs.filter((d) => d.regions?.includes(r)).length;
              return (
                <button
                  key={r}
                  type="button"
                  disabled={busy}
                  aria-pressed={on}
                  onClick={() => toggle(r)}
                  className={cn(
                    "inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50",
                    on
                      ? "border-primary bg-selected text-primary"
                      : "border-input bg-card text-foreground hover:bg-muted",
                  )}
                >
                  {on ? (
                    <Check className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <span className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  <span className="font-mono font-medium">{r}</span>
                  <span className={on ? undefined : "text-muted-foreground"}>
                    {n === 1 ? "1 doc" : `${n} docs`}
                  </span>
                </button>
              );
            })}
            {!everywhere && (
              <Button
                type="button"
                variant="link"
                size="sm"
                className="h-8 px-1.5 text-xs"
                disabled={busy}
                onClick={() => setChosen(choices)}
              >
                All Regions
              </Button>
            )}
          </div>
        </div>
      )}

      {choices.length < 2 && listed.length > 0 && (
        // the regions show, but there is nothing to choose: one region, or
        // regions listed together in one document, which share it
        <div className="space-y-2">
          <FieldLabel
            id={`${id}-regions`}
            helpId={`${id}-regions-help`}
            help={
              listed.length === 1
                ? `The value is for ${listed[0]}${unlabelled ? ", and the documents without a region" : ""}.`
                : sharesRegions(file)
                  ? `The value goes to ${regionList(listed)}: regions listed in one document share it, so they can't be sealed apart.`
                  : `The value goes to ${regionList(listed)}.`
            }
          >
            Regions
          </FieldLabel>
          <ul
            aria-labelledby={`${id}-regions`}
            aria-describedby={`${id}-regions-help`}
            className="flex flex-wrap items-center gap-1.5"
          >
            {listed.map((r) => (
              <li key={r}>
                <RegionTag region={r} />
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="space-y-2">
        <FieldLabel
          htmlFor={`${id}-value`}
          helpId={`${id}-value-help`}
          help="Encrypted as soon as it reaches the server; only the agent that seals it can read it."
        >
          Value
        </FieldLabel>
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
            aria-describedby={`${id}-value-help`}
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
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <SealProgress seal={seal} busy={busy} error={error} env={env} />
        <div className="flex shrink-0 items-center gap-3 sm:ml-auto">
          <span className="hidden items-center gap-1 text-xs text-muted-foreground md:flex">
            <Kbd>{modKey()}</Kbd>
            <Kbd>↵</Kbd>
          </span>
          <Button
            type="submit"
            size="sm"
            disabled={!canSubmit}
            className={cn(
              // as wide busy as idle, so the button doesn't jump
              "min-w-32",
              justSealed &&
                "bg-success text-success-foreground hover:bg-success/90 disabled:opacity-100",
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
 * Where a seal stands, in the terms of the person sealing: one agent seals,
 * but with the env key every cluster holds, so the value decrypts in every
 * cluster. Which agent sealed it, with which key, is behind an info icon;
 * naming one cluster up front reads as if the value worked only there.
 */
function SealProgress({
  seal,
  busy,
  error,
  env,
}: {
  seal: Seal | null;
  busy: boolean;
  error: string | null;
  env: string;
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
          {seal.status === "queued" ? "Waiting for an agent…" : "Sealing…"}
        </p>
      );
    case "sealed":
      return (
        <div className="flex items-center gap-1 text-sm">
          <p role="status" className="flex items-center gap-2">
            <CheckCircle2
              className="h-4 w-4 shrink-0 text-success"
              aria-hidden="true"
            />
            <span>
              Sealed <code className="font-mono text-xs">{seal.key}</code> for{" "}
              {documents(seal.targets.length)}
              {seal.regions?.length ? ` in ${regionList(seal.regions)}` : ""}.
              Every cluster in the {env} env can decrypt it.
            </span>
          </p>
          <InfoTip label="About This Seal">
            {agentName(seal)}&apos;s agent sealed it with the env key (
            <code className="font-mono">
              {shortFingerprint(seal.fingerprint)}
            </code>
            ). Every cluster in the {env} env holds that key, so one agent seals
            for all of them.
          </InfoTip>
        </div>
      );
    case "superseded":
      return (
        <p role="status" className="text-sm text-muted-foreground">
          Sealed <code className="font-mono text-xs">{seal.key}</code>, but a
          newer seal of it has replaced the value.
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
