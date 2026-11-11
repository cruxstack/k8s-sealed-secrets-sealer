import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/**
 * The heading row of a page section, above its table or cards: the title
 * with a muted count beside it on the left, and small muted notes or
 * controls on the right ("Refreshes every 15 seconds").
 */
export function SectionHeading({
  id,
  title,
  count,
  countClassName,
  aside,
}: {
  id: string;
  title: ReactNode;
  count?: ReactNode;
  countClassName?: string;
  aside?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
      <div className="flex items-baseline gap-2">
        <h2 id={id} className="text-base font-semibold">
          {title}
        </h2>
        {count !== undefined && (
          <span className={cn("text-sm text-muted-foreground", countClassName)}>
            {count}
          </span>
        )}
      </div>
      {aside && <div className="text-xs text-muted-foreground">{aside}</div>}
    </div>
  );
}

/**
 * The title of a section inside a card ("Files", "Keys"): `text-sm`
 * semibold, with its count as a secondary badge.
 */
export function CardHeading({
  as: Heading = "h2",
  id,
  count,
  children,
}: {
  as?: "h2" | "h3";
  id?: string;
  count?: number;
  children: ReactNode;
}) {
  return (
    <Heading id={id} className="flex items-center gap-2 text-sm font-semibold">
      {children}
      {count !== undefined && <Badge variant="secondary">{count}</Badge>}
    </Heading>
  );
}
