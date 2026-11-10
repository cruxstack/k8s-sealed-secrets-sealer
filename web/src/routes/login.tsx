import { createFileRoute, redirect } from "@tanstack/react-router";
import { FileLock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { resolveCurrentUser } from "@/lib/auth";
import { loginErrorMessage } from "@/lib/login-errors";
import { safeReturnPath } from "@/lib/utils";

interface LoginSearch {
  error?: string;
  return_to?: string;
}

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>): LoginSearch => {
    const out: LoginSearch = {};
    // The default search parser JSON-decodes values, so `?error=1` arrives as
    // a number; keep any scalar so unknown codes still show a message.
    const error = search.error;
    if (typeof error === "string" && error) out.error = error;
    if (typeof error === "number" || typeof error === "boolean") {
      out.error = String(error);
    }
    if (typeof search.return_to === "string" && search.return_to) {
      out.return_to = search.return_to;
    }
    return out;
  },
  beforeLoad: async ({ context, search }) => {
    if (await resolveCurrentUser(context.queryClient)) {
      throw redirect({ href: safeReturnPath(search.return_to), replace: true });
    }
  },
  component: LoginPage,
});

function LoginPage() {
  const { error, return_to } = Route.useSearch();
  const errorMessage = loginErrorMessage(error);
  const returnTo = safeReturnPath(return_to);
  const loginHref =
    returnTo === "/"
      ? "/api/v1/auth/login"
      : `/api/v1/auth/login?return_to=${encodeURIComponent(returnTo)}`;

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm space-y-8">
        <div className="flex flex-col items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary shadow-lg">
            <FileLock
              className="h-8 w-8 text-primary-foreground"
              aria-hidden="true"
            />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-tight">Sealer</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Sign in with your GitHub account to seal secrets for this
              environment.
            </p>
          </div>
        </div>

        {errorMessage && (
          <div
            role="alert"
            className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive"
          >
            {errorMessage}
          </div>
        )}

        <Button asChild className="w-full" size="lg">
          <a href={loginHref}>
            <svg
              className="mr-2 h-5 w-5"
              viewBox="0 0 24 24"
              fill="currentColor"
              aria-hidden="true"
            >
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            Sign in with GitHub
          </a>
        </Button>
      </div>
    </main>
  );
}
