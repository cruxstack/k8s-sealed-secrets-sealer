import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** A key or key combination, as shown in shortcut hints. */
export function Kbd({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-border bg-muted px-1 font-sans text-[11px] font-medium text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}
