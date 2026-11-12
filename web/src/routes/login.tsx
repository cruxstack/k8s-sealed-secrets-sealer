import { createFileRoute, redirect } from "@tanstack/react-router";
import { FileLock } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { GitHubMark } from "@/components/ui/github-mark";
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
              Sign in with your GitHub account to seal secrets for the envs your
              teams may use.
            </p>
          </div>
        </div>

        {errorMessage && (
          <Alert variant="destructive" role="alert">
            {errorMessage}
          </Alert>
        )}

        <Button asChild className="w-full" size="lg">
          <a href={loginHref}>
            <GitHubMark className="mr-2 h-5 w-5" />
            Sign In With GitHub
          </a>
        </Button>
      </div>
    </main>
  );
}
