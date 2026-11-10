import { useId } from "react";
import {
  ArrowRight,
  Check,
  CircleDashed,
  Minus,
  Plus,
  RefreshCw,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  regionList,
  type KeyState,
  type KeyStatus,
  type RegionKeyState,
  type RegionStatus,
} from "./keys";

/** What a key's state means for the file, in a few words. */
export function keyDetail(k: KeyStatus, docs: number): string {
  // per region, the chips beside it say the rest
  if (k.regions.length > 0) {
    const needed = k.regions.filter((r) => r.state !== "unneeded");
    const pendingIn = k.regions
      .filter((r) => r.state === "pending")
      .map((r) => r.region);
    switch (k.state) {
      case "set":
        return needed.length === k.regions.length
          ? "Set in every region"
          : "Set wherever it is needed";
      case "partial":
        return `Missing in ${regionList(
          k.regions
            .filter((r) => r.state === "missing" || r.state === "partial")
            .map((r) => r.region),
        )}`;
      case "missing":
        return "Expected, not set yet";
      case "new":
      case "replaced": {
        const what = k.state === "new" ? "New" : "New value";
        return pendingIn.length < needed.length
          ? `${what} pending for ${regionList(pendingIn)}`
          : k.state === "new"
            ? "New, in your pending changes"
            : "New value in your pending changes";
      }
    }
  }
  switch (k.state) {
    case "set":
      return docs === 1
        ? "Set"
        : k.needed === docs
          ? `In all ${docs} documents`
          : `In all ${k.needed} documents that need it`;
    case "partial":
      return `In ${k.needed - k.lacking.length} of ${k.needed}; not in ${k.lacking.join(", ")}`;
    case "missing":
      return k.needed === 1
        ? "Expected, not set yet"
        : `Expected, in none of the ${k.needed} documents`;
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

const REGION_LOOK: Record<
  RegionKeyState,
  { icon: typeof Check; chip: string; says: string }
> = {
  set: {
    icon: Check,
    chip: "border-border bg-background text-muted-foreground [&>svg]:text-success",
    says: "set",
  },
  pending: {
    icon: Plus,
    chip: "border-primary/30 bg-primary/10 text-primary dark:bg-primary/20",
    says: "pending",
  },
  partial: {
    icon: CircleDashed,
    chip: "border-warning/60 text-warning",
    says: "in some of its documents",
  },
  missing: {
    icon: CircleDashed,
    chip: "border-dashed border-warning/60 text-warning",
    says: "missing",
  },
  unneeded: {
    icon: Minus,
    chip: "border-transparent text-muted-foreground/80",
    says: "not needed: its hints leave the key out",
  },
};

/**
 * Where a key stands in each region, as chips. When values can be sealed,
 * a region's chip fills the form with the key, limited to that region.
 */
function RegionChips({
  k,
  onPick,
  disabled,
}: {
  k: KeyStatus;
  onPick?: (key: string, regions?: string[]) => void;
  disabled: boolean;
}) {
  return (
    <ul
      aria-label={`${k.key} by region`}
      className="flex basis-full flex-wrap gap-1 pb-1 pl-9 sm:basis-auto sm:pb-0 sm:pl-0"
    >
      {k.regions.map((r: RegionStatus) => {
        const look = REGION_LOOK[r.state];
        const Icon = look.icon;
        const name = r.region || "no region";
        const className = cn(
          "inline-flex h-6 items-center gap-1 rounded-md border px-1.5 font-mono text-xs",
          look.chip,
        );
        const body = (
          <>
            <Icon className="h-3 w-3" aria-hidden="true" />
            {name}
          </>
        );
        return (
          <li key={r.region}>
            {onPick && r.region ? (
              <button
                type="button"
                disabled={disabled}
                onClick={() => onPick(k.key, [r.region])}
                aria-label={`${name}: ${look.says}. Seal ${k.key} for ${name} only`}
                title={`${look.says}; seal for ${name} only`}
                className={cn(
                  className,
                  "transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-60",
                )}
              >
                {body}
              </button>
            ) : (
              <span
                className={className}
                aria-label={`${name}: ${look.says}`}
                title={look.says}
              >
                {body}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * A file's keys, one row each, with where each stands across the file's
 * documents and, when they are in more than one region, in each region.
 * When values can be sealed, picking a row fills the seal form's key, and
 * picking a region fills it for that region only.
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
  /**
   * Fill the seal form with a key, and with regions, limit it to them;
   * absent when values can't be sealed.
   */
  onPick?: (key: string, regions?: string[]) => void;
  /** A seal is running: the form's key can't change. */
  disabled?: boolean;
}) {
  const headingId = useId();
  const attention = keys.filter(
    (k) => k.state === "missing" || k.state === "partial",
  ).length;
  const regional = keys.some((k) => k.regions.length > 0);
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
            {regional
              ? "Pick a key to seal it everywhere, or a region to seal it there only."
              : "Pick a key to seal its value, or type a new one below."}
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
              <li
                key={k.key}
                className={cn(
                  "flex flex-wrap items-center gap-x-2 rounded-lg",
                  current === k.key &&
                    "bg-primary/8 ring-1 ring-primary/30 dark:bg-primary/15",
                )}
              >
                {onPick ? (
                  <button
                    type="button"
                    onClick={() => onPick(k.key)}
                    disabled={disabled}
                    aria-pressed={current === k.key}
                    className="group flex min-w-0 flex-1 flex-wrap items-center gap-x-2.5 gap-y-0.5 rounded-lg px-3 py-1.5 text-left transition-colors hover:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:pointer-events-none disabled:opacity-60"
                  >
                    {body}
                    <span className="ml-auto hidden shrink-0 items-center gap-1 pl-2 text-xs text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100 group-aria-pressed:opacity-100 sm:flex">
                      {look.action}
                      <ArrowRight className="h-3 w-3" aria-hidden="true" />
                    </span>
                  </button>
                ) : (
                  <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2.5 gap-y-0.5 px-3 py-1.5">
                    {body}
                  </div>
                )}
                {k.regions.length > 0 && (
                  <RegionChips k={k} onPick={onPick} disabled={disabled} />
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
