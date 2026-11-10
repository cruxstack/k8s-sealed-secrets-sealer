import { createFileRoute, redirect } from "@tanstack/react-router";
import { requireSignedIn } from "@/lib/require-auth";

// Sealing is what people come for: the home page is their repositories.
export const Route = createFileRoute("/")({
  beforeLoad: async (opts) => {
    await requireSignedIn(opts);
    throw redirect({ to: "/repos", replace: true });
  },
});
