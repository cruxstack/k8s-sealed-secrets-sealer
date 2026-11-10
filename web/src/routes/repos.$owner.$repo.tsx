import { createFileRoute, redirect } from "@tanstack/react-router";
import { homeEnv } from "@/lib/require-auth";
import { repoSearch } from "./$env.secrets.$owner.$repo";

// the sealing area moved to /{env}/secrets; old links keep their file
export const Route = createFileRoute("/repos/$owner/$repo")({
  validateSearch: repoSearch,
  beforeLoad: async (opts) => {
    const env = await homeEnv(opts);
    throw redirect({
      to: "/$env/secrets/$owner/$repo",
      params: { env, ...opts.params },
      search: opts.search,
      replace: true,
    });
  },
});
