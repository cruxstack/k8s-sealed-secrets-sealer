import { Toaster as Sonner } from "sonner";
import { useTheme } from "@/lib/theme-provider";

/**
 * Short-lived notices for things that happened (a value sealed, a change
 * removed). Never put a secret value in one. Errors that need action stay
 * in the page as alerts.
 */
export function Toaster() {
  const { theme } = useTheme();
  return (
    <Sonner
      theme={theme}
      position="bottom-right"
      closeButton
      toastOptions={{
        classNames: {
          toast:
            "rounded-xl! border-border! bg-card! text-card-foreground! shadow-lg!",
          description: "text-muted-foreground!",
          success: "[&_[data-icon]]:text-success!",
          error: "[&_[data-icon]]:text-destructive!",
        },
      }}
    />
  );
}
