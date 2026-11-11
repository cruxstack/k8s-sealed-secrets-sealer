import { Link, useLocation } from "@tanstack/react-router";
import { MapPinOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { SignedInPage } from "@/lib/require-auth";

/** A page that does not exist, in the app's shell, with the way home. */
export function NotFound() {
  const { pathname } = useLocation();
  return (
    <SignedInPage>
      <EmptyState
        page
        icon={MapPinOff}
        title="Page not found"
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/">Go to Secrets</Link>
          </Button>
        }
      >
        Nothing is at{" "}
        <code className="font-mono text-xs [overflow-wrap:anywhere] text-foreground">
          {pathname}
        </code>
        . Check the address, or start again from your secrets.
      </EmptyState>
    </SignedInPage>
  );
}
