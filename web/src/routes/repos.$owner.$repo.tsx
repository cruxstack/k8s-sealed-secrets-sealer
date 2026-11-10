import { createFileRoute, redirect } from "@tanstack/react-router";
import type { RepoSearch } from "./secrets.$owner.$repo";

// the sealing area moved to /secrets; old links keep their file
export const Route = createFileRoute("/repos/$owner/$repo")({
  validateSearch: (search: Record<string, unknown>): RepoSearch =>
    typeof search.file === "string" && search.file !== ""
      ? { file: search.file }
      : {},
  beforeLoad: ({ params, search }) => {
    throw redirect({
      to: "/secrets/$owner/$repo",
      params,
      search,
      replace: true,
    });
  },
});
