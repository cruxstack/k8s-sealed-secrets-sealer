import { createFileRoute, redirect } from "@tanstack/react-router";

// an env's home is its secrets
export const Route = createFileRoute("/$env/")({
  beforeLoad: ({ params }) => {
    throw redirect({ to: "/$env/secrets", params, replace: true });
  },
});
