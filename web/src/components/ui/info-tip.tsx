import { useId, useState, type ReactNode } from "react";
import { Info } from "lucide-react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

/**
 * An info icon with more to say: a field's help (`FieldLabel`), or how a
 * result came about. The text shows on hover, keyboard focus and a tap,
 * and is the button's description for a screen reader. Another element
 * can take it as its description too: give it `id` and point that
 * element's `aria-describedby` at it.
 */
export function InfoTip({
  id,
  label,
  children,
  className,
}: {
  id?: string;
  /** The button's name ("About Key"). */
  label: string;
  /** What it has to say, in a sentence or two. */
  children: ReactNode;
  className?: string;
}) {
  const own = useId();
  const textId = id ?? own;
  const [open, setOpen] = useState(false);
  return (
    <>
      <Tooltip open={open} onOpenChange={setOpen}>
        <TooltipTrigger asChild>
          <button
            type="button"
            aria-label={label}
            aria-describedby={textId}
            // a 24px target that adds no height to a line of text
            className={cn(
              "-my-1 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none data-[state=delayed-open]:text-foreground data-[state=instant-open]:text-foreground",
              className,
            )}
            onClick={(e) => {
              // the tooltip would close on a click; a tap is how a touch
              // screen asks for the text, so keep it open
              e.preventDefault();
              setOpen(true);
            }}
          >
            <Info className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </TooltipTrigger>
        {/* the text is a description already: the tooltip is for the eye,
            and holds only text, so clicks go through it */}
        <TooltipContent
          side="top"
          align="start"
          className="pointer-events-none text-left whitespace-normal"
          aria-hidden="true"
        >
          {children}
        </TooltipContent>
      </Tooltip>
      {/* hidden, it is still a description, but not read again on its own
          where it sits */}
      <span id={textId} hidden>
        {children}
      </span>
    </>
  );
}
