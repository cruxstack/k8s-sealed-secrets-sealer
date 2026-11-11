import { useId, useState } from "react";
import { cn } from "@/lib/utils";
import { Button, type ButtonProps } from "./button";
import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

/**
 * An icon-only ghost button, with what it does in a tooltip on hover and
 * keyboard focus. Name it with `aria-label`.
 *
 * With a `reason`, it cannot be used now: it is grayed out, does nothing
 * when clicked, and its tooltip says why. It stays focusable
 * (`aria-disabled`, not `disabled`, which takes no focus or pointer
 * events), so the reason reaches a keyboard, a screen reader (as its
 * description) and a touch screen, where a tap shows the tooltip.
 */
export function IconButton({
  label,
  reason,
  className,
  children,
  onClick,
  ...props
}: Omit<ButtonProps, "asChild" | "size" | "disabled"> & {
  /** What it does, at the top of the tooltip ("Revoke"). */
  label: string;
  /** Why it cannot be used now, as a sentence; unset when it can. */
  reason?: string;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const unavailable = reason !== undefined;
  return (
    <Tooltip open={open} onOpenChange={setOpen}>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          {...props}
          aria-disabled={unavailable || undefined}
          // always, not only while the tooltip shows
          aria-describedby={unavailable ? id : undefined}
          className={cn(
            unavailable && "cursor-not-allowed opacity-50 hover:bg-transparent",
            className,
          )}
          onClick={(e) => {
            if (!unavailable) {
              onClick?.(e);
              return;
            }
            // the tooltip would close on a click; a tap is how a touch
            // screen asks why, so keep it open
            e.preventDefault();
            setOpen(true);
          }}
        >
          {children}
        </Button>
      </TooltipTrigger>
      {/* the label is all a screen reader needs from the tooltip: the
          reason is the button's description already. It holds only text,
          so clicks go through it: in a column of icons it covers the next
          row's, which must still take a click */}
      <TooltipContent
        side="top"
        className="pointer-events-none text-left whitespace-normal"
        data-click-through=""
        aria-label={label}
      >
        <p className="font-medium">{label}</p>
        {unavailable && <p className="text-muted-foreground">{reason}</p>}
      </TooltipContent>
      {unavailable && (
        <span id={id} className="sr-only">
          {reason}
        </span>
      )}
    </Tooltip>
  );
}
