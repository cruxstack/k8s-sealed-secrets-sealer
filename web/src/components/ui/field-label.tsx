import { type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { InfoTip } from "./info-tip";
import { Label } from "./label";

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
      <InfoTip id={helpId} label={`About ${children}`}>
        {help}
      </InfoTip>
    </div>
  );
}
