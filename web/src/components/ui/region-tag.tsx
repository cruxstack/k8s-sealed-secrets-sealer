import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/**
 * The look of a region wherever one is shown: a small bordered tag in
 * monospace `text-xs`. Chips that act on a region (the key list's) add
 * their state's colors and a button to it.
 */
export const regionTagClass =
  "inline-flex h-5 items-center gap-1 rounded-md border px-1.5 font-mono text-xs leading-none whitespace-nowrap";

/** A region's name as a tag; documents without one are "no region". */
export function RegionTag({
  region,
  className,
  ...props
}: { region: string } & HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        regionTagClass,
        "border-border bg-background text-foreground",
        !region && "font-sans",
        className,
      )}
      {...props}
    >
      {region || "no region"}
    </span>
  );
}
