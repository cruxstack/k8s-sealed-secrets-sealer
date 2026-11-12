import { useId, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

/**
 * Something in a row with more to say than the row has room for: a
 * status's who and when, a count's breakdown. The row shows only what
 * matters at a glance (the badge, the count); the rest is a tooltip on
 * hover, keyboard focus and a tap, and the description a screen reader
 * reads with it.
 */
export function HoverDetail({
  detail,
  children,
  className,
}: {
  /** What the row leaves out, as text: a line or two. */
  detail: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  return (
    <Tooltip open={open} onOpenChange={setOpen}>
      <TooltipTrigger asChild>
        <span
          // focusable, so the detail reaches a keyboard too
          tabIndex={0}
          aria-describedby={id}
          className={cn(
            "inline-flex cursor-default items-center rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
            className,
          )}
          onClick={(e) => {
            // the tooltip would close on a click; a tap is how a touch
            // screen asks for the detail, so keep it open
            e.preventDefault();
            setOpen(true);
          }}
        >
          {children}
        </span>
      </TooltipTrigger>
      {/* the detail is the trigger's description already: the tooltip is
          for the eye, and holds only text, so clicks go through it */}
      <TooltipContent
        side="top"
        className="pointer-events-none text-left whitespace-normal"
        aria-hidden="true"
      >
        {detail}
      </TooltipContent>
      {/* hidden, it is still the trigger's description, but not read as
          part of the cell or the sentence around it */}
      <span id={id} hidden>
        {detail}
      </span>
    </Tooltip>
  );
}
