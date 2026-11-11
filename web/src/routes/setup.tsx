import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FileLock } from "lucide-react";
import { extractApiError, navigation } from "@/api/client";
import { setupStatusQueryOptions, startSetup } from "@/api/queries/setup";
import type { SetupStatus } from "@/api/types";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { GitHubMark } from "@/components/ui/github-mark";
import { Skeleton } from "@/components/ui/skeleton";
import { setupErrorMessage } from "@/lib/setup-errors";

interface SetupSearch {
  error?: string;
}

export const Route = createFileRoute("/setup")({
  validateSearch: (search: Record<string, unknown>): SetupSearch => {
    // the default search parser JSON-decodes values; keep any scalar so
    // unknown codes still show a message
    const error = search.error;
    if (typeof error === "string" && error) return { error };
    if (typeof error === "number" || typeof error === "boolean") {
      return { error: String(error) };
    }
    return {};
  },
  component: SetupPage,
});

const PERMISSION_LABELS: Readonly<Record<string, string>> = {
  contents: "Contents",
  pull_requests: "Pull requests",
  metadata: "Metadata",
  members: "Members (organization)",
};

const PERMISSION_USES: Readonly<Record<string, string>> = {
  contents: "reads SealedSecret files, and commits sealed values to a branch",
  pull_requests: "opens the pull requests with sealed values",
  metadata: "lists the repositories it is installed on",
  members: "checks people's teams when they sign in",
};

function SetupPage() {
  const { error } = Route.useSearch();
  const { data, isLoading, isError } = useQuery(setupStatusQueryOptions);

  return (
    <main className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-lg space-y-8">
        <div className="flex flex-col items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary shadow-lg">
            <FileLock
              className="h-8 w-8 text-primary-foreground"
              aria-hidden="true"
            />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-tight">Set up Sealer</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Sealer reads and writes your repositories, and signs people in, as
              a GitHub App in your organization.
            </p>
          </div>
        </div>

        {isLoading ? (
          <Skeleton className="h-72 w-full rounded-xl" />
        ) : isError ? (
          <Alert variant="destructive" role="alert">
            The setup couldn't be loaded. Refresh the page.
          </Alert>
        ) : data ? (
          <CreateApp setup={data} error={setupErrorMessage(error)} />
        ) : (
          <SetUp />
        )}
      </div>
    </main>
  );
}

/** Creating the App: what it asks for, and the button that goes to GitHub. */
function CreateApp({
  setup,
  error,
}: {
  setup: SetupStatus;
  error: string | null;
}) {
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  async function create() {
    setStarting(true);
    setStartError(null);
    try {
      const form = await startSetup();
      // GitHub shows the App, lets you rename it, and creates it
      navigation.postForm(form.action, { manifest: form.manifest });
    } catch (err) {
      setStartError(extractApiError(err));
      setStarting(false);
    }
  }

  const message = startError ?? error;
  return (
    <div className="space-y-4">
      {message && (
        <Alert variant="destructive" role="alert">
          {message}
        </Alert>
      )}
      <Card>
        <CardContent className="space-y-5 p-6 text-sm">
          <ol className="list-decimal space-y-1.5 pl-5">
            <li>
              Create the App in <strong>{setup.org}</strong> on GitHub. Only an
              owner of the organization can. GitHub suggests{" "}
              <strong>{setup.app_name}</strong>; you can rename it there.
            </li>
            <li>
              Install it on the repositories that hold your SealedSecrets.
            </li>
            <li>Sign in to Sealer with GitHub.</li>
          </ol>

          <div className="space-y-2">
            <h2 className="font-medium">The App asks for</h2>
            <ul className="divide-y rounded-lg border">
              {setup.permissions.map((p) => (
                <li
                  key={p.name}
                  className="flex flex-col gap-0.5 px-3 py-2 sm:flex-row sm:items-baseline sm:justify-between sm:gap-4"
                >
                  <span>
                    <span className="font-medium">
                      {PERMISSION_LABELS[p.name] ?? p.name}
                    </span>
                    <span className="text-muted-foreground">
                      {" "}
                      · {PERMISSION_USES[p.name] ?? ""}
                    </span>
                  </span>
                  <span className="shrink-0 text-muted-foreground">
                    {p.access === "write" ? "Read and write" : "Read"}
                  </span>
                </li>
              ))}
            </ul>
            <p className="text-muted-foreground">
              No webhook, and only your organization can install it.
            </p>
          </div>

          <Button
            type="button"
            className="w-full"
            size="lg"
            disabled={starting}
            onClick={() => void create()}
          >
            <GitHubMark className="mr-2 h-5 w-5" />
            {starting
              ? "Opening GitHub…"
              : `Create the GitHub App in ${setup.org}`}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

/** Once the App is set up, this page only points to signing in. */
function SetUp() {
  return (
    <Alert
      variant="success"
      heading="Sealer is set up"
      action={
        <Button asChild size="sm" variant="outline">
          <Link to="/login">Sign in</Link>
        </Button>
      }
    >
      Its GitHub App is created. Install it on more repositories from your
      organization's settings on GitHub.
    </Alert>
  );
}
