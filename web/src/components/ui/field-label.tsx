import { useState, type ReactNode } from "react";
import { Info } from "lucide-react";
import { cn } from "@/lib/utils";
import { Label } from "./label";
import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

/**
 * A form field's name with its help behind an info icon beside it, instead
 * of a line of small print under the control. The help shows on hover,
 * keyboard focus and a tap, and stays the control's description for a
 * screen reader: point the control's `aria-describedby` at `helpId`.
 *
 * With `htmlFor` the name labels that control; without it the name is a
 * group's, which takes it with `aria-labelledby` and `id`.
 */
export function FieldLabel({
  children,
  htmlFor,
  id,
  help,
  helpId,
  className,
}: {
  /** The field's name ("Key"); the info button is "About Key". */
  children: string;
  htmlFor?: string;
  id?: string;
  /** What the field is for, in a sentence or two. */
  help: ReactNode;
  helpId: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className={cn("flex items-center gap-1", className)}>
      {htmlFor ? (
        <Label htmlFor={htmlFor} id={id}>
          {children}
        </Label>
      ) : (
        // a group's name, styled as a label
        <span id={id} className="text-sm leading-none font-medium">
          {children}
        </span>
      )}
      <Tooltip open={open} onOpenChange={setOpen}>
        <TooltipTrigger asChild>
          <button
            type="button"
            aria-label={`About ${children}`}
            aria-describedby={helpId}
            // a 24px target that adds no height to the row
            className="-my-1 inline-flex h-6 w-6 items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none data-[state=delayed-open]:text-foreground data-[state=instant-open]:text-foreground"
            onClick={(e) => {
              // the tooltip would close on a click; a tap is how a touch
              // screen asks for the help, so keep it open
              e.preventDefault();
              setOpen(true);
            }}
          >
            <Info className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </TooltipTrigger>
        {/* the help is the description of the control and of this button
            already: the tooltip is for the eye, and holds only text, so
            clicks go through it */}
        <TooltipContent
          side="top"
          align="start"
          className="pointer-events-none text-left whitespace-normal"
          aria-hidden="true"
        >
          {help}
        </TooltipContent>
      </Tooltip>
      {/* hidden, it is still a description, but not read again on its own
          between the name and the control */}
      <span id={helpId} hidden>
        {help}
      </span>
    </div>
  );
}
