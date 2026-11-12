import {
  useId,
  useImperativeHandle,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type Ref,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, X } from "lucide-react";
import { toast } from "sonner";
import { extractApiError } from "@/api/client";
import {
  RESEAL_KEY,
  createSchedule,
  updateSchedule,
} from "@/api/queries/reseal";
import { useReposQueryOptions } from "@/api/queries/repos";
import type { ResealSchedule, ResealScheduleInput } from "@/api/types";
import { plural } from "@/components/fleet/references";
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
import { Input } from "@/components/ui/input";
import { Kbd } from "@/components/ui/kbd";
import { Label } from "@/components/ui/label";
import { modKey } from "@/lib/shortcuts";
import { cn, relativeTime, sentence } from "@/lib/utils";
import {
  LIMITS,
  firstRunAt,
  formatDate,
  intervalHint,
  orgProblem,
  repoProblem,
  scheduleProblems,
} from "./format";

/** A new schedule's interval: a little under a quarter. */
export const DEFAULT_INTERVAL_DAYS = 75;

interface ChipInputHandle {
  focus: () => void;
  /**
   * Adds what is typed, and returns every value; null when what is typed
   * is not valid, which the field then says.
   */
  flush: () => string[] | null;
}

/**
 * A list of values typed one at a time: Enter or a comma adds what is
 * typed as a chip once it is valid, Backspace in the empty field removes
 * the last, and Enter in the empty field moves on. Pasted lists are split
 * on commas and spaces.
 */
function ChipInput({
  ref,
  id,
  values,
  onChange,
  check,
  max,
  noun,
  placeholder,
  help,
  problem: outer,
  suggestions,
  onNext,
}: {
  ref: Ref<ChipInputHandle>;
  id: string;
  values: string[];
  onChange: (values: string[]) => void;
  /** Why a value is not valid, or null. */
  check: (value: string) => string | null;
  max: number;
  /** What a value is: "repository", "org". */
  noun: string;
  placeholder: string;
  help: string;
  /** What is wrong with the whole list, from the form. */
  problem?: string;
  suggestions: string[];
  onNext: () => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [text, setText] = useState("");
  const [problem, setProblem] = useState<string | null>(null);

  /** Adds what is typed; the values after, or null when it is not valid. */
  const add = (raw: string): string[] | null => {
    const items = raw
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const next = [...values];
    for (const [i, item] of items.entries()) {
      const why =
        check(item) ??
        (next.some((v) => v.toLowerCase() === item.toLowerCase())
          ? `${item} is already added.`
          : next.length >= max
            ? `A schedule takes at most ${plural(max, noun)}.`
            : null);
      if (why) {
        // keep what was added, and leave the rest to fix
        onChange(next);
        setText(items.slice(i).join(", "));
        setProblem(why);
        return null;
      }
      next.push(item);
    }
    if (next.length !== values.length) onChange(next);
    setText("");
    setProblem(null);
    return next;
  };

  useImperativeHandle(ref, () => ({
    focus: () => input.current?.focus(),
    flush: () => (text.trim() === "" ? values : add(text)),
  }));

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (plainEnter(e)) {
      if (text.trim() === "") onNext();
      else add(text);
    } else if (e.key === ",") {
      e.preventDefault();
      if (text.trim() !== "") add(text);
    } else if (e.key === "Backspace" && text === "" && values.length > 0) {
      onChange(values.slice(0, -1));
    }
  };
  const shown = problem ?? outer;

  return (
    <>
      <div
        className={cn(
          "flex min-h-10 flex-wrap items-center gap-1.5 rounded-md border bg-background px-2 py-1.5 shadow-xs focus-within:ring-2",
          shown
            ? "border-destructive focus-within:ring-destructive"
            : "border-input focus-within:ring-ring",
        )}
        onClick={(e) => {
          if (e.target === e.currentTarget) input.current?.focus();
        }}
      >
        {values.map((v) => (
          <span
            key={v}
            className="inline-flex h-6 max-w-full items-center gap-0.5 rounded-md border border-border bg-muted pl-1.5 font-mono text-xs"
          >
            <span className="truncate">{v}</span>
            <button
              type="button"
              aria-label={`Remove ${v}`}
              title={`Remove ${v}`}
              onClick={() => onChange(values.filter((x) => x !== v))}
              className="inline-flex h-6 w-5 items-center justify-center rounded-md text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              <X className="h-3 w-3" aria-hidden="true" />
            </button>
          </span>
        ))}
        <input
          ref={input}
          id={id}
          list={`${id}-suggestions`}
          className="h-7 min-w-32 flex-1 bg-transparent font-mono text-sm outline-none placeholder:font-sans placeholder:text-muted-foreground [&::-webkit-calendar-picker-indicator]:hidden!"
          placeholder={values.length === 0 ? placeholder : undefined}
          autoComplete="off"
          spellCheck={false}
          value={text}
          aria-invalid={shown ? true : undefined}
          aria-describedby={`${id}-help`}
          onChange={(e) => {
            setText(e.target.value);
            setProblem(null);
          }}
          onKeyDown={onKeyDown}
          onBlur={() => {
            if (text.trim() !== "") add(text);
          }}
        />
        <datalist id={`${id}-suggestions`}>
          {suggestions
            .filter((s) => !values.includes(s))
            .map((s) => (
              <option key={s} value={s} />
            ))}
        </datalist>
      </div>
      <p
        id={`${id}-help`}
        className={cn(
          "text-xs",
          shown ? "text-destructive" : "text-muted-foreground",
        )}
      >
        {shown ?? help}
      </p>
    </>
  );
}

/**
 * Whether a key press is Enter alone, which moves to the next field; its
 * default (submitting) is prevented.
 */
function plainEnter(e: KeyboardEvent<HTMLInputElement>): boolean {
  if (e.key !== "Enter" || e.metaKey || e.ctrlKey) return false;
  e.preventDefault();
  return true;
}

/** The fields of a schedule that differ from what it was. */
function changed(
  before: ResealSchedule,
  after: ResealScheduleInput,
): Partial<ResealScheduleInput> {
  const same = (a: string[], b: string[]) =>
    a.length === b.length && a.every((v, i) => v === b[i]);
  const patch: Partial<ResealScheduleInput> = {};
  if (after.name !== before.name) patch.name = after.name;
  if (!same(after.repos, before.repos)) patch.repos = after.repos;
  if (!same(after.orgs, before.orgs)) patch.orgs = after.orgs;
  if (after.interval_days !== before.interval_days) {
    patch.interval_days = after.interval_days;
  }
  if (after.enabled !== before.enabled) patch.enabled = after.enabled;
  return patch;
}

/** The days typed, or NaN when they are not a whole number. */
function parseDays(text: string): number {
  return /^\d+$/.test(text.trim()) ? Number(text.trim()) : Number.NaN;
}

/**
 * When the schedule runs next, once saved: "First run in 75 days, on Jan
 * 25, 2027." A new or resumed schedule first runs an interval from now; an
 * edit that keeps it running and its interval keeps its next run.
 */
function preview(
  schedule: ResealSchedule | undefined,
  days: number,
  enabled: boolean,
  now: Date,
): string | null {
  if (!enabled) {
    return "Paused: it doesn't run until you resume it. Run Now still works.";
  }
  if (
    schedule?.enabled &&
    schedule.next_run_at &&
    schedule.interval_days === days
  ) {
    return `Next run ${relativeTime(schedule.next_run_at, now)}, on ${formatDate(new Date(schedule.next_run_at))}.`;
  }
  if (
    !Number.isInteger(days) ||
    days < LIMITS.minDays ||
    days > LIMITS.maxDays
  ) {
    return null;
  }
  const lead = schedule ? "Next run" : "First run";
  return `${lead} in ${plural(days, "day")}, on ${formatDate(firstRunAt(days, now))}.`;
}

function ScheduleForm({
  schedule,
  now,
  onBusyChange,
  onDone,
}: {
  schedule?: ResealSchedule;
  now: Date;
  onBusyChange: (busy: boolean) => void;
  onDone: () => void;
}) {
  const id = useId();
  const queryClient = useQueryClient();
  const editing = schedule !== undefined;
  const nameRef = useRef<HTMLInputElement>(null);
  const reposRef = useRef<ChipInputHandle>(null);
  const orgsRef = useRef<ChipInputHandle>(null);
  const daysRef = useRef<HTMLInputElement>(null);
  const enabledRef = useRef<HTMLInputElement>(null);
  const [name, setName] = useState(schedule?.name ?? "");
  const [repos, setRepos] = useState<string[]>(schedule?.repos ?? []);
  const [orgs, setOrgs] = useState<string[]>(schedule?.orgs ?? []);
  const [days, setDays] = useState(
    String(schedule?.interval_days ?? DEFAULT_INTERVAL_DAYS),
  );
  const [enabled, setEnabled] = useState(schedule?.enabled ?? true);
  // problems show once the form was sent, not while it is filled in
  const [tried, setTried] = useState(false);
  // suggestions: the repositories the user can read, and their owners
  const { data: readable } = useQuery({
    ...useReposQueryOptions(),
    select: (list) => list.repositories,
  });
  const repoSuggestions = (readable ?? []).map((r) => r.full_name);
  const orgSuggestions = [...new Set((readable ?? []).map((r) => r.owner))];

  const interval = parseDays(days);
  const input: ResealScheduleInput = {
    name: name.trim(),
    repos,
    orgs,
    interval_days: interval,
    enabled,
  };
  const problems = tried ? scheduleProblems(input) : {};
  const hint = intervalHint(interval);
  const next = preview(schedule, interval, enabled, now);

  const save = useMutation({
    mutationFn: async (body: ResealScheduleInput) => {
      if (!schedule) return createSchedule(body);
      const patch = changed(schedule, body);
      return Object.keys(patch).length === 0
        ? schedule
        : updateSchedule(schedule.id, patch);
    },
    onMutate: () => onBusyChange(true),
    onSettled: () => onBusyChange(false),
    onSuccess: (saved) => {
      void queryClient.invalidateQueries({ queryKey: RESEAL_KEY });
      toast.success(editing ? `Saved ${saved.name}` : `Created ${saved.name}`, {
        description:
          saved.enabled && saved.next_run_at
            ? `${editing ? "Next" : "First"} run ${relativeTime(saved.next_run_at)}.`
            : "Paused: it runs once you resume it.",
      });
      onDone();
    },
  });

  function submit(e?: FormEvent) {
    e?.preventDefault();
    if (save.isPending) return;
    setTried(true);
    const r = reposRef.current?.flush() ?? repos;
    const o = orgsRef.current?.flush() ?? orgs;
    if (r === null || o === null) return;
    const body = { ...input, repos: r, orgs: o };
    const found = scheduleProblems(body);
    if (found.name) nameRef.current?.focus();
    else if (found.scope) reposRef.current?.focus();
    else if (found.interval) daysRef.current?.focus();
    else save.mutate(body);
  }

  // Enter moves to the next field; ⌘/Ctrl+Enter saves from any of them
  const onFormKeyDown = (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      submit();
    }
  };

  return (
    <form
      onSubmit={submit}
      onKeyDown={onFormKeyDown}
      aria-label={editing ? `Edit ${schedule.name}` : "New Schedule"}
      className="grid gap-4"
      noValidate
    >
      <DialogHeader>
        <DialogTitle>{editing ? "Edit Schedule" : "New Schedule"}</DialogTitle>
        <DialogDescription>
          Every so many days, a run reseals the values of these repositories
          that are on older keys, and opens a pull request in each one with
          values to move.
        </DialogDescription>
      </DialogHeader>

      <div className="space-y-1.5">
        <Label htmlFor={`${id}-name`}>Name</Label>
        <Input
          ref={nameRef}
          id={`${id}-name`}
          className="h-10"
          placeholder="e.g. Platform repositories"
          maxLength={LIMITS.name}
          autoComplete="off"
          value={name}
          aria-invalid={problems.name ? true : undefined}
          aria-describedby={problems.name ? `${id}-name-help` : undefined}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (plainEnter(e)) reposRef.current?.focus();
          }}
        />
        {problems.name && (
          <p id={`${id}-name-help`} className="text-xs text-destructive">
            {problems.name}
          </p>
        )}
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${id}-repos`}>Repositories</Label>
        <ChipInput
          ref={reposRef}
          id={`${id}-repos`}
          values={repos}
          onChange={setRepos}
          check={repoProblem}
          max={LIMITS.repos}
          noun="repository"
          placeholder="owner/name, then Enter"
          help={`Each as owner/name; up to ${LIMITS.repos}.`}
          problem={problems.scope}
          suggestions={repoSuggestions}
          onNext={() => orgsRef.current?.focus()}
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${id}-orgs`}>Orgs</Label>
        <ChipInput
          ref={orgsRef}
          id={`${id}-orgs`}
          values={orgs}
          onChange={setOrgs}
          check={orgProblem}
          max={LIMITS.orgs}
          noun="org"
          placeholder="An org's login, then Enter"
          help={`Every repository of the org the GitHub App is installed on, apart from archived ones; up to ${LIMITS.orgs}.`}
          suggestions={orgSuggestions}
          onNext={() => daysRef.current?.focus()}
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${id}-days`}>Every</Label>
        <div className="flex items-center gap-2">
          <Input
            ref={daysRef}
            id={`${id}-days`}
            type="number"
            inputMode="numeric"
            min={LIMITS.minDays}
            max={LIMITS.maxDays}
            step={1}
            className="h-10 w-24 tabular-nums"
            value={days}
            aria-invalid={problems.interval ? true : undefined}
            aria-describedby={`${id}-days-help`}
            onChange={(e) => setDays(e.target.value)}
            onKeyDown={(e) => {
              if (plainEnter(e)) enabledRef.current?.focus();
            }}
          />
          <span className="text-sm">days</span>
        </div>
        <p
          id={`${id}-days-help`}
          className={cn(
            "text-xs",
            problems.interval ? "text-destructive" : "text-muted-foreground",
          )}
        >
          {problems.interval ??
            hint ??
            `From ${LIMITS.minDays} to ${LIMITS.maxDays} days.`}
        </p>
      </div>

      <div className="space-y-1.5">
        <div className="flex items-center gap-2">
          <input
            ref={enabledRef}
            id={`${id}-enabled`}
            type="checkbox"
            className="h-4 w-4 rounded border-input accent-primary"
            checked={enabled}
            aria-describedby={`${id}-preview`}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <Label htmlFor={`${id}-enabled`}>Enabled</Label>
        </div>
        <p
          id={`${id}-preview`}
          className={cn(
            "text-xs",
            enabled ? "text-foreground" : "text-muted-foreground",
          )}
        >
          {next}
        </p>
      </div>

      {save.error && (
        <Alert variant="destructive" role="alert">
          Could not {editing ? "save" : "create"} the schedule:{" "}
          {sentence(extractApiError(save.error))}
        </Alert>
      )}

      <DialogFooter className="sm:items-center">
        <span className="mr-auto hidden items-center gap-1 text-xs text-muted-foreground sm:flex">
          <Kbd>{modKey()}</Kbd>
          <Kbd>↵</Kbd>
          <span className="ml-1">to save</span>
        </span>
        <DialogClose asChild>
          <Button type="button" variant="outline" disabled={save.isPending}>
            Cancel
          </Button>
        </DialogClose>
        <Button
          type="submit"
          className="min-w-36"
          disabled={save.isPending}
          aria-keyshortcuts="Meta+Enter Control+Enter"
        >
          {save.isPending && (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
          )}
          {save.isPending
            ? "Saving…"
            : editing
              ? "Save Changes"
              : "Create Schedule"}
        </Button>
      </DialogFooter>
    </form>
  );
}

/** Creates a schedule, or edits one, in a dialog. */
export function ScheduleDialog({
  open,
  schedule,
  now,
  onClose,
}: {
  open: boolean;
  /** The schedule to edit; a new one when unset. */
  schedule?: ResealSchedule;
  now: Date;
  onClose: () => void;
}) {
  const busy = useRef(false);
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o && !busy.current) onClose();
      }}
    >
      <DialogContent className="max-h-[calc(100dvh-2rem)] max-w-xl overflow-y-auto">
        {open && (
          <ScheduleForm
            key={schedule?.id ?? "new"}
            schedule={schedule}
            now={now}
            onBusyChange={(b) => {
              busy.current = b;
            }}
            onDone={onClose}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
