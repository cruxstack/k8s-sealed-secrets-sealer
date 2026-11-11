import { Toaster as Sonner } from "sonner";
import { useTheme } from "@/lib/theme-provider";

/** Below the 3.5rem header, with the page's 1rem gutter. */
const OFFSET = { top: 72, right: 16 };

/**
 * Short-lived notices for things that happened (a change removed, a key
 * revoked). Never put a secret value in one. Errors that need action stay
 * in the page as alerts. Toasts sit top right, under the header, so they
 * never cover the seal form or the pending changes.
 */
export function Toaster() {
  const { resolvedTheme } = useTheme();
  return (
    <Sonner
      theme={resolvedTheme}
      position="top-right"
      offset={OFFSET}
      mobileOffset={OFFSET}
      closeButton
      toastOptions={{
        classNames: {
          toast:
            "rounded-xl! border-border! bg-card! text-card-foreground! shadow-lg!",
          description: "text-muted-foreground!",
          // sonner draws its own close disc; give it the card's colors and
          // the app's focus ring
          closeButton:
            "bg-card! border-border! text-muted-foreground! hover:bg-accent! hover:text-foreground! focus-visible:ring-2! focus-visible:ring-ring! focus-visible:shadow-none!",
          success: "[&_[data-icon]]:text-success!",
          error: "[&_[data-icon]]:text-destructive!",
          warning: "[&_[data-icon]]:text-warning!",
          info: "[&_[data-icon]]:text-info!",
        },
      }}
    />
  );
}
