import type { HTMLAttributes, ReactNode } from "react";
import { cva } from "class-variance-authority";
import {
  CircleAlert,
  CircleCheck,
  Info,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

type AlertVariant = "info" | "success" | "warning" | "destructive";

const alertVariants = cva(
  "flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm text-foreground",
  {
    variants: {
      variant: {
        info: "border-info/40 bg-info-subtle",
        success: "border-success/40 bg-success-subtle",
        warning: "border-warning/40 bg-warning-subtle",
        destructive: "border-destructive/40 bg-destructive-subtle",
      },
    },
  },
);

const ICONS: Record<AlertVariant, { icon: LucideIcon; color: string }> = {
  info: { icon: Info, color: "text-info" },
  success: { icon: CircleCheck, color: "text-success" },
  warning: { icon: TriangleAlert, color: "text-warning" },
  destructive: { icon: CircleAlert, color: "text-destructive" },
};

export interface AlertProps extends Omit<
  HTMLAttributes<HTMLDivElement>,
  "title"
> {
  /**
   * What kind of notice: info (informational, list may be incomplete),
   * success (done), warning (needs attention), destructive (failed or
   * unavailable).
   */
  variant: AlertVariant;
  /** A short first line in medium weight; the children explain it. */
  heading?: ReactNode;
  /** Replaces the variant's icon; null for none. */
  icon?: LucideIcon | null;
  /** Buttons or links on the right; they wrap below on a phone. */
  action?: ReactNode;
}

/**
 * A notice in the page: an icon in the variant's color, an optional
 * heading, the text, and optional actions. Errors that appear after an
 * action take `role="alert"`; standing notices take `role="status"` or no
 * role.
 */
export function Alert({
  variant,
  heading,
  icon,
  action,
  className,
  children,
  ...props
}: AlertProps) {
  const Icon = icon === undefined ? ICONS[variant].icon : icon;
  return (
    <div className={cn(alertVariants({ variant }), className)} {...props}>
      {Icon && (
        <Icon
          className={cn("mt-0.5 h-4 w-4 shrink-0", ICONS[variant].color)}
          aria-hidden="true"
        />
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-x-4 gap-y-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1">
          {heading && <p className="font-medium">{heading}</p>}
          {children && <div>{children}</div>}
        </div>
        {action && (
          <div className="flex shrink-0 flex-wrap items-center gap-1 sm:-my-1">
            {action}
          </div>
        )}
      </div>
    </div>
  );
}
