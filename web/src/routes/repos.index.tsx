import { createFileRoute, redirect } from "@tanstack/react-router";

// the sealing area moved to /secrets
export const Route = createFileRoute("/repos/")({
  beforeLoad: () => {
    throw redirect({ to: "/secrets", replace: true });
  },
});
