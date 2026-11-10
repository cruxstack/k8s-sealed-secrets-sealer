import { useId } from "react";
import { ArrowRight, Check, CircleDashed, Plus, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { KeyState, KeyStatus } from "./keys";

/** What a key's state means for the file, in a few words. */
export function keyDetail(k: KeyStatus, docs: number): string {
  switch (k.state) {
    case "set":
      return docs === 1 ? "Set" : `In all ${docs} documents`;
    case "partial":
      return `In ${k.holders} of ${docs}; not in ${k.lacking.join(", ")}`;
    case "missing":
      return docs === 1
        ? "Expected, not set yet"
        : `Expected, in none of the ${docs} documents`;
    case "new":
      return "New, in your pending changes";
    case "replaced":
      return "New value in your pending changes";
  }
}

const LOOK: Record<
  KeyState,
  { icon: typeof Check; iconClass: string; text: string; action: string }
> = {
  set: {
    icon: Check,
    iconClass: "text-success",
    text: "text-muted-foreground",
    action: "Replace",
  },
  partial: {
    icon: CircleDashed,
    iconClass: "text-warning",
    text: "text-warning",
    action: "Seal",
  },
  missing: {
    icon: CircleDashed,
    iconClass: "text-warning",
    text: "text-warning",
    action: "Seal",
  },
  new: {
    icon: Plus,
    iconClass: "text-primary",
    text: "text-primary",
    action: "Seal again",
  },
  replaced: {
    icon: RefreshCw,
    iconClass: "text-primary",
    text: "text-primary",
    action: "Seal again",
  },
};

/**
 * A file's keys, one row each, with where each stands across the file's
 * documents. When values can be sealed, picking a row fills the seal form's
 * key with it.
 */
export function KeyList({
  keys,
  docs,
  current,
  onPick,
  disabled = false,
}: {
  keys: KeyStatus[];
  /** How many documents the file has for the env. */
  docs: number;
  /** The key in the seal form. */
  current?: string;
  /** Fill the seal form with a key; absent when values can't be sealed. */
  onPick?: (key: string) => void;
  /** A seal is running: the form's key can't change. */
  disabled?: boolean;
}) {
  const headingId = useId();
  const attention = keys.filter(
    (k) => k.state === "missing" || k.state === "partial",
  ).length;
  return (
    <section aria-labelledby={headingId}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-5 pt-4 pb-2">
        <div className="flex items-center gap-2">
          <h3
            id={headingId}
            className="flex items-center gap-2 text-sm font-semibold"
          >
            Keys
            <Badge variant="secondary">{keys.length}</Badge>
          </h3>
          {attention > 0 && (
            <span className="text-xs text-warning">{attention} to seal</span>
          )}
        </div>
        {onPick && keys.length > 0 && (
          <p className="text-xs text-muted-foreground">
            Pick a key to seal its value, or type a new one below.
          </p>
        )}
      </div>
      {keys.length === 0 ? (
        <p className="px-5 pb-4 text-sm text-muted-foreground">
          No keys yet.{onPick && " Seal a value to add the first one."}
        </p>
      ) : (
        <ul aria-label="Keys" className="px-2 pb-2">
          {keys.map((k) => {
            const look = LOOK[k.state];
            const Icon = look.icon;
            const detail = keyDetail(k, docs);
            const body = (
              <>
                <Icon
                  className={cn("h-3.5 w-3.5 shrink-0", look.iconClass)}
                  aria-hidden="true"
                />
                <code className="shrink-0 font-mono text-[13px] font-medium">
                  {k.key}
                </code>
                <span
                  className={cn(
                    "min-w-0 basis-full pl-6 text-xs sm:basis-auto sm:pl-0",
                    look.text,
                  )}
                >
                  {detail}
                </span>
              </>
            );
            return (
              <li key={k.key}>
                {onPick ? (
                  <button
                    type="button"
                    onClick={() => onPick(k.key)}
                    disabled={disabled}
                    aria-pressed={current === k.key}
                    className={cn(
                      "group flex w-full flex-wrap items-center gap-x-2.5 gap-y-0.5 rounded-lg px-3 py-1.5 text-left transition-colors hover:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:pointer-events-none disabled:opacity-60",
                      current === k.key &&
                        "bg-primary/8 ring-1 ring-primary/30 dark:bg-primary/15",
                    )}
                  >
                    {body}
                    <span className="ml-auto hidden shrink-0 items-center gap-1 pl-2 text-xs text-muted-foreground opacity-0 sm:flex transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100 group-aria-pressed:opacity-100">
                      {look.action}
                      <ArrowRight className="h-3 w-3" aria-hidden="true" />
                    </span>
                  </button>
                ) : (
                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-0.5 px-3 py-1.5">
                    {body}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
