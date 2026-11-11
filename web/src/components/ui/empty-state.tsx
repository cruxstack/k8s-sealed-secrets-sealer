import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * A screen or section with nothing to show, or nothing the user may see:
 * an icon, a title that says what is missing, a line that says why and what
 * to do about it, and the way forward as an outline button. As a page's
 * only content (no access, not found) its title is the page's h1.
 */
export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
  page = false,
  className,
}: {
  icon: LucideIcon;
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  /** The title is the page's h1. */
  page?: boolean;
  className?: string;
}) {
  const Title = page ? "h1" : "p";
  return (
    <Card className={cn(page && "mx-auto max-w-lg", className)}>
      <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
        <Icon className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
        <Title
          className={
            page ? "text-xl font-semibold tracking-tight" : "font-semibold"
          }
        >
          {title}
        </Title>
        {children && (
          <div className="max-w-md text-sm text-muted-foreground">
            {children}
          </div>
        )}
        {action && (
          <div className="flex flex-wrap justify-center gap-2 pt-2">
            {action}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
