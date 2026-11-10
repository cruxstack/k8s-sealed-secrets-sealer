import { Component, Suspense, type ErrorInfo, type ReactNode } from "react";
import {
  createRootRouteWithContext,
  Outlet,
  type ErrorComponentProps,
} from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { AuthProvider } from "@/lib/auth";

export const Route = createRootRouteWithContext<{
  queryClient: QueryClient;
}>()({
  component: RootComponent,
  errorComponent: RouteError,
});

function ErrorPanel({ title, message }: { title: string; message: string }) {
  return (
    <div className="flex h-screen items-center justify-center p-8">
      <div role="alert" className="max-w-md space-y-4 text-center">
        <h1 className="text-2xl font-bold">{title}</h1>
        <p className="text-muted-foreground">
          Try navigating back or refreshing the page.
        </p>
        <pre className="max-h-40 overflow-auto rounded-md bg-muted p-4 text-left text-xs">
          {message}
        </pre>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Refresh page
        </button>
      </div>
    </div>
  );
}

interface ErrorBoundaryState {
  error: Error | null;
}

class ErrorBoundary extends Component<
  { children: ReactNode },
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled error:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <ErrorPanel
          title="Something went wrong"
          message={this.state.error.message}
        />
      );
    }
    return this.props.children;
  }
}

function RouteError({ error }: ErrorComponentProps) {
  const message =
    error instanceof Error ? error.message : "An unexpected error occurred.";
  return <ErrorPanel title="Page error" message={message} />;
}

function PageSkeleton() {
  return (
    <div className="flex h-screen items-center justify-center">
      <div
        className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"
        role="status"
        aria-label="Loading"
      />
    </div>
  );
}

function RootComponent() {
  // Routes render their own layout (signed-in pages wrap themselves in
  // AppShell). Choosing the shell here from the router location would
  // remount the page whenever a navigation starts, before the new route has
  // loaded.
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Suspense fallback={<PageSkeleton />}>
          <Outlet />
        </Suspense>
        <Toaster />
      </AuthProvider>
    </ErrorBoundary>
  );
}
