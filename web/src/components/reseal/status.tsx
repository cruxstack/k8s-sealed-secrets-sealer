import { Building2, FolderGit2 } from "lucide-react";
import type {
  ResealPullRequestState,
  ResealRunRepo,
  ResealRunStatus,
} from "@/api/types";
import { Fingerprint } from "@/components/fleet/KeyDialogs";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type Look = { label: string; variant: BadgeProps["variant"] };

/** A run's status as a badge: its color says what kind, its word what. */
const RUN_STATUS: Record<ResealRunStatus, Look> = {
  queued: { label: "Queued", variant: "info" },
  running: { label: "Running", variant: "info" },
  succeeded: { label: "Succeeded", variant: "success" },
  partial: { label: "Partial", variant: "warning" },
  failed: { label: "Failed", variant: "destructive" },
  cancelled: { label: "Cancelled", variant: "outline" },
};

export function RunStatusBadge({ status }: { status: ResealRunStatus }) {
  const look = RUN_STATUS[status];
  return <Badge variant={look.variant}>{look.label}</Badge>;
}

const REPO_STATUS: Record<ResealRunRepo["status"], Look> = {
  pending: { label: "Pending", variant: "outline" },
  resealing: { label: "Resealing", variant: "info" },
  opening: { label: "Opening PR", variant: "info" },
  opened: { label: "PR Opened", variant: "success" },
  unchanged: { label: "Unchanged", variant: "secondary" },
  skipped: { label: "Skipped", variant: "outline" },
  failed: { label: "Failed", variant: "destructive" },
};

export function RepoStatusBadge({
  status,
}: {
  status: ResealRunRepo["status"];
}) {
  const look = REPO_STATUS[status];
  return <Badge variant={look.variant}>{look.label}</Badge>;
}

const PR_STATE: Record<ResealPullRequestState, Look> = {
  // open: waiting on someone to merge it, like a pending change
  open: { label: "Open", variant: "info" },
  merged: { label: "Merged", variant: "success" },
  closed: { label: "Closed", variant: "secondary" },
};

export function PullRequestStateBadge({
  state,
}: {
  state: ResealPullRequestState;
}) {
  const look = PR_STATE[state];
  return <Badge variant={look.variant}>{look.label}</Badge>;
}

/** How far something has got: a thin bar with its count for assistive tech. */
export function Progress({
  done,
  total,
  label,
  className,
}: {
  done: number;
  total: number;
  /** What is counted ("Repositories done"). */
  label: string;
  className?: string;
}) {
  const pct = total > 0 ? Math.min(100, Math.round((done * 100) / total)) : 0;
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={total}
      aria-valuenow={done}
      aria-valuetext={`${done} of ${total}`}
      className={cn("h-1.5 overflow-hidden rounded-full bg-muted", className)}
    >
      <div
        className="h-full rounded-full bg-primary transition-[width]"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

const chipClass =
  "inline-flex h-6 max-w-56 items-center gap-1 rounded-md border border-border bg-background px-1.5 font-mono text-xs whitespace-nowrap";

/** A repository or an org in a schedule's scope. */
export function ScopeChip({
  value,
  org = false,
}: {
  value: string;
  org?: boolean;
}) {
  const Icon = org ? Building2 : FolderGit2;
  return (
    <span
      className={chipClass}
      title={org ? `Every repository of ${value}` : value}
    >
      <Icon
        className="h-3 w-3 shrink-0 text-muted-foreground"
        aria-hidden="true"
      />
      <span className="truncate">{value}</span>
      {org && <span className="sr-only"> (org)</span>}
    </span>
  );
}

/**
 * A schedule's repositories and orgs as chips, the first few of them, then
 * "+N" with the rest in its title.
 */
export function ScopeChips({
  repos,
  orgs,
  max = 3,
}: {
  repos: string[];
  orgs: string[];
  max?: number;
}) {
  const all = [
    ...orgs.map((value) => ({ value, org: true })),
    ...repos.map((value) => ({ value, org: false })),
  ];
  const shown = all.slice(0, max);
  const rest = all.slice(max);
  return (
    <span className="flex flex-wrap items-center gap-1">
      {shown.map((c) => (
        <ScopeChip key={`${c.org}:${c.value}`} {...c} />
      ))}
      {rest.length > 0 && (
        <span
          className={cn(chipClass, "font-sans text-muted-foreground")}
          title={rest
            .map((c) => (c.org ? `${c.value} (org)` : c.value))
            .join("\n")}
          aria-label={`and ${rest.length} more: ${rest.map((c) => c.value).join(", ")}`}
        >
          +{rest.length}
        </span>
      )}
    </span>
  );
}

/** Key fingerprints, short, the first two of them, then "+N". */
export function Fingerprints({
  values,
  max = 2,
}: {
  values: string[];
  max?: number;
}) {
  const rest = values.slice(max);
  return (
    <span className="flex flex-col items-start gap-0.5">
      {values.slice(0, max).map((fp) => (
        <Fingerprint
          key={fp}
          value={fp}
          className="text-xs whitespace-nowrap"
        />
      ))}
      {rest.length > 0 && (
        <span className="text-xs text-muted-foreground" title={rest.join("\n")}>
          and {rest.length} more
        </span>
      )}
    </span>
  );
}
