import { useRef, useState, type KeyboardEvent } from "react";
import { Search } from "lucide-react";
import type { PendingChange, RepositoryFile } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Kbd } from "@/components/ui/kbd";
import { useShortcut } from "@/lib/shortcuts";
import { cn } from "@/lib/utils";
import { fileHints } from "./hints";
import { missingKeys, pendingDocs } from "./keys";

export type FileStatus = "ready" | "blocked" | "unreadable";

/** Whether values can be sealed into a file, and if not, why not. */
export function fileStatus(file: RepositoryFile): FileStatus {
  if (file.error) return "unreadable";
  const docs = file.documents ?? [];
  if (docs.length === 0 || docs.some((d) => d.problem)) return "blocked";
  return "ready";
}

const STATUS: Record<FileStatus, { label: string; dot: string }> = {
  ready: { label: "Ready", dot: "bg-success" },
  blocked: { label: "Can't seal", dot: "bg-warning" },
  unreadable: { label: "Unreadable", dot: "bg-destructive" },
};

/** A path with its directory muted and its file name strong. */
export function FilePath({ path }: { path: string }) {
  const slash = path.lastIndexOf("/");
  return (
    <span className="font-mono break-all">
      {slash >= 0 && (
        <span className="text-muted-foreground">
          {path.slice(0, slash + 1)}
        </span>
      )}
      <span className="font-medium text-foreground">
        {path.slice(slash + 1)}
      </span>
    </span>
  );
}

function summary(file: RepositoryFile): string {
  const docs = file.documents ?? [];
  const status = fileStatus(file);
  if (status === "unreadable") return "Unreadable";
  const regions = [...new Set(docs.map((d) => d.region).filter(Boolean))];
  const count = docs.length === 1 ? "1 document" : `${docs.length} documents`;
  const where = regions.length > 0 ? ` · ${regions.join(", ")}` : "";
  return status === "blocked" ? `${count} · Can't seal` : `${count}${where}`;
}

/**
 * The files of a repository that hold SealedSecrets for the env, to pick one
 * from. `/` focuses the filter; Enter there opens the first match, and the
 * arrow keys move through the list.
 */
export function FileList({
  files,
  selected,
  changes,
  globs,
  onSelect,
}: {
  files: RepositoryFile[];
  selected: string | undefined;
  /** The session's pending changes. */
  changes: readonly PendingChange[];
  globs: string[];
  onSelect: (path: string) => void;
}) {
  const [filter, setFilter] = useState("");
  const filterRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  useShortcut("/", () => filterRef.current?.focus());

  const needle = filter.trim().toLowerCase();
  // a file matches on its path or on what it is for
  const shown = needle
    ? files.filter(
        (f) =>
          f.path.toLowerCase().includes(needle) ||
          fileHints(f).description?.toLowerCase().includes(needle),
      )
    : files;

  const buttons = () =>
    Array.from(listRef.current?.querySelectorAll("button") ?? []);
  const move = (e: KeyboardEvent<HTMLElement>, from: number) => {
    const all = buttons();
    if (e.key === "ArrowDown") {
      e.preventDefault();
      all[Math.min(from + 1, all.length - 1)]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (from <= 0) filterRef.current?.focus();
      else all[from - 1]?.focus();
    }
  };

  return (
    <section
      aria-labelledby="files-heading"
      className="flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card"
    >
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <h2
          id="files-heading"
          className="flex items-center gap-2 text-sm font-semibold"
        >
          Files
          <Badge variant="secondary">{files.length}</Badge>
        </h2>
      </div>
      <div className="relative border-b border-border p-2">
        <Search
          className="pointer-events-none absolute top-1/2 left-4.5 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden="true"
        />
        <Input
          ref={filterRef}
          type="search"
          name="file-filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && shown[0]) {
              e.preventDefault();
              onSelect(shown[0].path);
            } else if (e.key === "ArrowDown") {
              e.preventDefault();
              buttons()[0]?.focus();
            } else if (e.key === "Escape") {
              setFilter("");
            }
          }}
          placeholder="Filter files"
          aria-label="Filter files"
          className="h-9 pr-9 pl-8"
        />
        <Kbd className="pointer-events-none absolute top-1/2 right-4 -translate-y-1/2">
          /
        </Kbd>
      </div>
      {shown.length === 0 ? (
        <p className="px-4 py-6 text-center text-sm text-muted-foreground">
          No file matches “{filter.trim()}”.
        </p>
      ) : (
        <ul
          ref={listRef}
          className="min-h-0 space-y-0.5 overflow-y-auto p-1.5"
          aria-label="Files"
        >
          {shown.map((f, i) => {
            const status = fileStatus(f);
            const isSelected = f.path === selected;
            const count = changes.filter((c) => c.path === f.path).length;
            const { description } = fileHints(f);
            const missing =
              status === "unreadable"
                ? []
                : missingKeys(f, pendingDocs(changes, f.path));
            return (
              <li key={f.path}>
                <button
                  type="button"
                  onClick={() => onSelect(f.path)}
                  onKeyDown={(e) => move(e, i)}
                  aria-current={isSelected ? "true" : undefined}
                  className={cn(
                    "group w-full rounded-lg border border-transparent px-3 py-2 text-left text-[13px] transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                    isSelected
                      ? "border-primary/30 bg-primary/8 dark:bg-primary/15"
                      : "hover:bg-muted/70",
                  )}
                >
                  <span className="flex items-start gap-2">
                    <span
                      className={cn(
                        "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                        STATUS[status].dot,
                      )}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 flex-1">
                      <FilePath path={f.path} />
                      {description && (
                        <span
                          className="mt-0.5 block truncate text-xs text-foreground/80"
                          title={description}
                        >
                          {description}
                        </span>
                      )}
                      {/* the badges wrap below the summary as one group */}
                      <span className="mt-0.5 flex flex-wrap items-center justify-between gap-x-2 gap-y-1 text-xs text-muted-foreground">
                        <span className="whitespace-nowrap">{summary(f)}</span>
                        <span className="flex shrink-0 items-center gap-1">
                          {missing.length > 0 && (
                            <Badge
                              variant="outline"
                              className="border-dashed border-warning/60 text-warning"
                              title={`Expected but not set: ${missing.join(", ")}`}
                            >
                              {missing.length} missing
                              <span className="sr-only">
                                {missing.length === 1 ? " key" : " keys"}
                              </span>
                            </Badge>
                          )}
                          {count > 0 && (
                            <Badge className="shrink-0">
                              {count}{" "}
                              <span className="sr-only">
                                {count === 1
                                  ? "pending change"
                                  : "pending changes"}
                              </span>
                              <span aria-hidden="true">pending</span>
                            </Badge>
                          )}
                        </span>
                      </span>
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <p className="mt-auto shrink-0 border-t border-border px-4 py-2.5 text-xs text-muted-foreground">
        Searched{" "}
        {globs.map((g, i) => (
          <span key={g}>
            {i > 0 && ", "}
            <code className="font-mono">{g}</code>
          </span>
        ))}
      </p>
    </section>
  );
}
