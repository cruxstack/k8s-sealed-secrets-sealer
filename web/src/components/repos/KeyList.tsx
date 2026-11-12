import { useEffect, useId, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  CircleDashed,
  Minus,
  Plus,
  RefreshCw,
  RotateCcw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { FilterInput } from "@/components/ui/filter-input";
import { regionTagClass } from "@/components/ui/region-tag";
import { CardHeading } from "@/components/ui/section-heading";
import { cn } from "@/lib/utils";
import { keyProblem } from "./SealForm";
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
    const revokedIn = k.regions
      .filter((r) => r.state === "revoked")
      .map((r) => r.region);
    switch (k.state) {
      case "revoked":
        return revokedIn.length < needed.length
          ? `Sealed with a revoked key in ${regionList(revokedIn)}; seal it again`
          : "Sealed with a revoked key; seal it again";
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
        if (k.resealed) return "Resealed, in your pending changes";
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
      return k.resealed
        ? "Resealed, in your pending changes"
        : "New value in your pending changes";
    case "revoked":
      return "Sealed with a revoked key; seal it again";
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
    iconClass: "text-info",
    text: "text-info",
    action: "Replace",
  },
  replaced: {
    icon: RefreshCw,
    iconClass: "text-info",
    text: "text-info",
    action: "Replace",
  },
  revoked: {
    icon: RotateCcw,
    iconClass: "text-warning",
    text: "text-warning",
    action: "Seal Again",
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
    chip: "border-info/40 bg-info-subtle text-info",
    says: "pending",
  },
  revoked: {
    icon: RotateCcw,
    chip: "border-warning/60 bg-warning-subtle text-warning",
    says: "sealed with a revoked key, seal again",
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
    chip: "border-transparent text-muted-foreground",
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
        const className = cn(regionTagClass, "h-6", look.chip);
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

/** From this many keys, the list gets a filter and scrolls on its own. */
export const LONG_KEY_LIST = 12;

type KeyView = "all" | "seal" | "pending";

/** The keys each view of a long list shows. */
const IN_VIEW: Record<KeyView, (k: KeyStatus) => boolean> = {
  all: () => true,
  // missing somewhere, or sealed with a revoked key: both need a value
  seal: (k) =>
    k.state === "missing" || k.state === "partial" || k.state === "revoked",
  pending: (k) => k.state === "new" || k.state === "replaced",
};

const VIEW_LABEL: Record<KeyView, string> = {
  all: "All",
  seal: "To Seal",
  pending: "Pending",
};

/**
 * A file's keys, one row each, with where each stands across the file's
 * documents and, when they are in more than one region, in each region.
 * When values can be sealed, picking a row fills the seal form's key, and
 * picking a region fills it for that region only. A long list (a file with
 * dozens of keys) gets a filter and a choice of the keys to seal or those
 * pending, and scrolls in a box of its own, so the form stays close under
 * it; the key in the form is scrolled into view there.
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
  const [filter, setFilter] = useState("");
  const [view, setView] = useState<KeyView>("all");
  const filterRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const long = keys.length >= LONG_KEY_LIST;
  const counts: Record<KeyView, number> = {
    all: keys.length,
    seal: keys.filter(IN_VIEW.seal).length,
    pending: keys.filter(IN_VIEW.pending).length,
  };
  // a view emptied by sealing falls back to every key
  const active: KeyView = long && counts[view] > 0 ? view : "all";
  const needle = long ? filter.trim().toLowerCase() : "";
  const shown = keys.filter(
    (k) => IN_VIEW[active](k) && k.key.toLowerCase().includes(needle),
  );
  const regional = keys.some((k) => k.regions.length > 0);
  // a key the filter names that the file lacks can be sealed as a new one
  const typed = filter.trim();
  const newKey =
    onPick &&
    typed !== "" &&
    keyProblem(typed) === null &&
    !keys.some((k) => k.key === typed)
      ? typed
      : null;

  // the key in the form stays in view in a long list, which scrolls on
  // its own; the page itself never moves
  useEffect(() => {
    const box = listRef.current;
    if (!long || !box || !current) return;
    const row = Array.from(box.children).find(
      (el): el is HTMLElement =>
        el instanceof HTMLElement && el.dataset.key === current,
    );
    if (!row) return;
    if (row.offsetTop < box.scrollTop) {
      box.scrollTop = row.offsetTop - 4;
    } else if (
      row.offsetTop + row.offsetHeight >
      box.scrollTop + box.clientHeight
    ) {
      box.scrollTop = row.offsetTop + row.offsetHeight - box.clientHeight + 4;
    }
  }, [long, current, active, needle]);

  const rows = shown.map((k) => {
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
        data-key={k.key}
        className={cn(
          "flex flex-wrap items-center gap-x-2 rounded-lg",
          current === k.key && "bg-selected ring-1 ring-primary",
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
  });

  return (
    <section aria-labelledby={headingId}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-4 pt-4 pb-2">
        <div className="flex items-center gap-2">
          <CardHeading as="h3" id={headingId} count={keys.length}>
            Keys
          </CardHeading>
          {counts.seal > 0 && (
            <span className="text-xs text-warning">{counts.seal} to seal</span>
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
      {long && (
        <div className="flex flex-wrap items-center gap-2 px-4 pb-2">
          <FilterInput
            inputRef={filterRef}
            shortcut={false}
            className="w-full sm:w-60"
            inputClassName="h-8"
            name="key-filter"
            value={filter}
            onValueChange={setFilter}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                setFilter("");
              } else if (e.key === "Enter" && onPick && !disabled) {
                // the first match, or a new key, goes to the form
                const first = shown[0]?.key ?? newKey;
                if (first) {
                  e.preventDefault();
                  onPick(first);
                }
              }
            }}
            placeholder="Filter keys"
            aria-label="Filter keys"
          />
          {(counts.seal > 0 || counts.pending > 0) && (
            <div
              role="group"
              aria-label="Show keys"
              // one joined group as tall as the filter: each segment owns
              // its part of the outline, so the chosen one's edge is the
              // group's edge, with nothing inset
              className="inline-flex h-8 rounded-md shadow-xs dark:shadow-none"
            >
              {(["all", "seal", "pending"] as const)
                .filter((v) => v === "all" || counts[v] > 0)
                .map((v) => (
                  <button
                    key={v}
                    type="button"
                    aria-pressed={active === v}
                    onClick={() => setView(v)}
                    className={cn(
                      "relative -ml-px inline-flex items-center gap-1.5 border px-3 text-xs font-medium transition-colors first:ml-0 first:rounded-l-md last:rounded-r-md focus-visible:z-20 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                      active === v
                        ? // above its neighbours, so its whole edge shows
                          "z-10 border-primary bg-selected text-primary"
                        : "border-input bg-card text-muted-foreground hover:bg-muted hover:text-foreground",
                    )}
                  >
                    {VIEW_LABEL[v]}{" "}
                    <span className="tabular-nums">{counts[v]}</span>
                  </button>
                ))}
            </div>
          )}
          {shown.length < keys.length && shown.length > 0 && (
            <span
              className="text-xs text-muted-foreground tabular-nums sm:ml-auto"
              role="status"
            >
              {shown.length} of {keys.length}
            </span>
          )}
        </div>
      )}
      {keys.length === 0 ? (
        <p className="px-4 pb-4 text-sm text-muted-foreground">
          No keys yet.{onPick && " Seal a value to add the first one."}
        </p>
      ) : shown.length === 0 ? (
        <div className="mx-4 mb-4 space-y-2 rounded-lg border border-dashed px-4 py-5 text-center text-sm text-muted-foreground">
          <p>No key matches “{typed}”.</p>
          <div className="flex flex-wrap justify-center gap-2">
            {newKey && (
              <Button
                variant="outline"
                size="sm"
                disabled={disabled}
                onClick={() => onPick?.(newKey)}
              >
                {/* one span: the button's flex box would drop the spaces */}
                <span>
                  Seal <code className="font-mono">{newKey}</code> as a New Key
                </span>
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setFilter("");
                filterRef.current?.focus();
              }}
            >
              Clear Filter
            </Button>
          </div>
        </div>
      ) : long ? (
        // the box scrolls on its own, so the form below stays close
        <div className="mx-4 mb-4 overflow-hidden rounded-lg border border-border">
          <ul
            ref={listRef}
            aria-label="Keys"
            className="relative max-h-[min(20rem,40vh)] overflow-y-auto overscroll-contain p-1"
          >
            {rows}
          </ul>
        </div>
      ) : (
        <ul aria-label="Keys" className="px-1 pb-2">
          {rows}
        </ul>
      )}
    </section>
  );
}
