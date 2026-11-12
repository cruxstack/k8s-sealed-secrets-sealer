import { Fragment, useRef, useState, type KeyboardEvent } from "react";
import type { PendingChange, RepositoryFile } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FilterInput } from "@/components/ui/filter-input";
import { CardHeading } from "@/components/ui/section-heading";
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

/**
 * A path with its directory muted and its file name strong. It wraps only
 * after a slash, so a folder's name is never split.
 */
export function FilePath({ path }: { path: string }) {
  const slash = path.lastIndexOf("/");
  const folders = path.slice(0, slash + 1).split(/(?<=\/)/);
  return (
    <span className="font-mono [overflow-wrap:anywhere]">
      {slash >= 0 && (
        <span className="text-muted-foreground">
          {folders.map((f, i) => (
            <Fragment key={i}>
              {f}
              <wbr />
            </Fragment>
          ))}
        </span>
      )}
      <span className="font-medium text-foreground">
        {path.slice(slash + 1)}
      </span>
    </span>
  );
}

/**
 * A path on one line, as a list shows it: the file name whole, and as much
 * of its directory as fits before it, cut at the start ("…/billing/"),
 * since the folders nearest a file tell it from the others. The whole
 * path is its title. `quiet` mutes the file name too, for a path under a
 * file's title.
 */
export function PathLine({
  path,
  quiet = false,
  className,
}: {
  path: string;
  quiet?: boolean;
  className?: string;
}) {
  const slash = path.lastIndexOf("/");
  const dir = path.slice(0, slash + 1);
  return (
    <span className={cn("flex min-w-0 font-mono", className)} title={path}>
      {/* read as one path, without the marks and the cut */}
      <span className="sr-only">{path}</span>
      {dir && (
        // right to left, so the ellipsis cuts the start; the marks keep the
        // slashes on the side they belong
        <span
          className="min-w-0 truncate text-muted-foreground [direction:rtl]"
          aria-hidden="true"
        >
          {`\u200e${dir}\u200e`}
        </span>
      )}
      <span
        className={cn(
          "max-w-full shrink-0 truncate",
          quiet ? "text-muted-foreground" : "font-medium text-foreground",
        )}
        aria-hidden="true"
      >
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
  // a file matches on its path, its title or what it is for
  const shown = needle
    ? files.filter((f) => {
        const { title, description } = fileHints(f);
        return [f.path, title, description].some((t) =>
          t?.toLowerCase().includes(needle),
        );
      })
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
      className="flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card shadow-xs dark:shadow-none"
    >
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <CardHeading id="files-heading" count={files.length}>
          Files
        </CardHeading>
      </div>
      <div className="border-b border-border p-2">
        <FilterInput
          inputRef={filterRef}
          name="file-filter"
          value={filter}
          onValueChange={setFilter}
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
        />
      </div>
      {shown.length === 0 ? (
        <div className="space-y-2 px-4 py-6 text-center text-sm text-muted-foreground">
          <p>No file matches “{filter.trim()}”.</p>
          <Button variant="outline" size="sm" onClick={() => setFilter("")}>
            Clear filter
          </Button>
        </div>
      ) : (
        <ul
          ref={listRef}
          className="min-h-0 space-y-0.5 overflow-y-auto p-1.5"
          aria-label="Files"
        >
          {shown.map((f, i) => {
            const status = fileStatus(f);
            const isSelected = f.path === selected;
            const mine = changes.filter((c) => c.path === f.path);
            const stale = mine.filter((c) => c.key_revoked).length;
            const count = mine.length - stale;
            const { title, description } = fileHints(f);
            const missing =
              status === "unreadable"
                ? []
                : missingKeys(f, pendingDocs(changes, f.path));
            const badges = missing.length > 0 || count > 0 || stale > 0;
            return (
              <li key={f.path}>
                <button
                  type="button"
                  onClick={() => onSelect(f.path)}
                  onKeyDown={(e) => move(e, i)}
                  aria-current={isSelected ? "true" : undefined}
                  className={cn(
                    "group w-full rounded-lg border px-2.5 py-2 text-left text-[13px] transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                    isSelected
                      ? "border-primary bg-selected"
                      : "border-transparent hover:bg-muted/70",
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
                      {/* one line each, never wrapped: a title when the
                          file has one, over its path */}
                      {title ? (
                        <>
                          <span
                            className="block truncate font-medium text-foreground"
                            title={title}
                          >
                            {title}
                          </span>
                          <PathLine
                            path={f.path}
                            quiet
                            className="mt-0.5 text-xs"
                          />
                        </>
                      ) : (
                        <PathLine path={f.path} />
                      )}
                      {description && (
                        <span
                          className="mt-0.5 block truncate text-xs text-foreground"
                          title={description}
                        >
                          {description}
                        </span>
                      )}
                      <span className="mt-0.5 block text-xs text-muted-foreground">
                        {summary(f)}
                      </span>
                      {/* the badges always get their own row, left-aligned */}
                      {badges && (
                        <span className="mt-1.5 flex flex-wrap items-center gap-1">
                          {stale > 0 && (
                            <Badge
                              variant="warning"
                              title="Sealed with a key an admin has since revoked: seal again, or remove it"
                            >
                              Seal again
                              <span className="sr-only">
                                {stale === 1
                                  ? " 1 pending change"
                                  : ` ${stale} pending changes`}
                              </span>
                            </Badge>
                          )}
                          {count > 0 && (
                            <Badge variant="info">
                              {count}{" "}
                              <span className="sr-only">
                                {count === 1
                                  ? "pending change"
                                  : "pending changes"}
                              </span>
                              <span aria-hidden="true">pending</span>
                            </Badge>
                          )}
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
                        </span>
                      )}
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
