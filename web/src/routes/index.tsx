import { createFileRoute, redirect } from "@tanstack/react-router";
import { homeEnv } from "@/lib/require-auth";

// Sealing is what people come for: the home page is the secrets of the
// first env they may use.
export const Route = createFileRoute("/")({
  beforeLoad: async (opts) => {
    const env = await homeEnv(opts);
    throw redirect({ to: "/$env/secrets", params: { env }, replace: true });
  },
});
