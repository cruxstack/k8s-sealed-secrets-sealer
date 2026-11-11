import type {
  HTMLAttributes,
  TableHTMLAttributes,
  TdHTMLAttributes,
  ThHTMLAttributes,
} from "react";
import { cn } from "@/lib/utils";

/**
 * The one table shell: a rounded, bordered box with a light shadow that
 * scrolls sideways on its own, so the page never does. It is `relative` so
 * visually hidden text inside it stays inside it too.
 */
export function Table({
  className,
  containerClassName,
  ...props
}: TableHTMLAttributes<HTMLTableElement> & { containerClassName?: string }) {
  return (
    <div
      className={cn(
        "relative overflow-x-auto rounded-xl border bg-card shadow-xs dark:shadow-none",
        containerClassName,
      )}
    >
      <table className={cn("w-full text-sm", className)} {...props} />
    </div>
  );
}

/** Column headers: short, uppercase, muted, on a tinted band. */
export function TableHeader({
  className,
  ...props
}: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead
      className={cn(
        "border-b border-border bg-muted/40 text-xs tracking-wide whitespace-nowrap text-muted-foreground uppercase",
        className,
      )}
      {...props}
    />
  );
}

export function TableHead({
  className,
  scope = "col",
  ...props
}: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope={scope}
      className={cn("px-4 py-2.5 text-left font-semibold", className)}
      {...props}
    />
  );
}

export function TableRow({
  className,
  ...props
}: HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn("border-b border-border last:border-0", className)}
      {...props}
    />
  );
}

export function TableCell({
  className,
  ...props
}: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("px-4 py-3", className)} {...props} />;
}

/** An empty cell: an em dash, in the sans font even in a monospace column. */
export function Dash() {
  return (
    <span className="font-sans text-muted-foreground" aria-label="none">
      —
    </span>
  );
}
