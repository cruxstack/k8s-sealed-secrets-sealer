import { useId, useState } from "react";
import { cn } from "@/lib/utils";
import { Button, type ButtonProps } from "./button";
import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

/**
 * A labelled button that, with a `reason`, cannot be used now, where the
 * reason does not fit in text under it (a heading row, a card's header).
 * Like `IconButton`'s: it is grayed out and does nothing when clicked, it
 * stays focusable (`aria-disabled`), its reason is its description, and a
 * tooltip shows the reason on hover, focus and a tap.
 */
export function ReasonButton({
  reason,
  className,
  onClick,
  ...props
}: Omit<ButtonProps, "asChild" | "disabled"> & {
  /** Why it cannot be used now, as a sentence; unset when it can. */
  reason?: string;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  if (reason === undefined) {
    return <Button className={className} onClick={onClick} {...props} />;
  }
  return (
    <Tooltip open={open} onOpenChange={setOpen}>
      <TooltipTrigger asChild>
        <Button
          type="button"
          {...props}
          aria-disabled
          aria-describedby={id}
          className={cn("cursor-not-allowed opacity-50", className)}
          onClick={(e) => {
            // a tap is how a touch screen asks why: keep the tooltip open
            e.preventDefault();
            setOpen(true);
          }}
        />
      </TooltipTrigger>
      <TooltipContent
        side="top"
        className="pointer-events-none text-left whitespace-normal"
      >
        {reason}
      </TooltipContent>
      <span id={id} className="sr-only">
        {reason}
      </span>
    </Tooltip>
  );
}
