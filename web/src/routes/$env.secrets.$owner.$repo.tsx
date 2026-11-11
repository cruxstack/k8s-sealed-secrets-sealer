import { createFileRoute } from "@tanstack/react-router";
import { RepoWorkspace } from "@/components/repos/RepoWorkspace";
import { SignedInPage } from "@/lib/require-auth";

export interface RepoSearch {
  /** The chosen file's path. */
  file?: string;
}

/** A repository page's search: the chosen file, when there is one. */
export function repoSearch(search: Record<string, unknown>): RepoSearch {
  return typeof search.file === "string" && search.file !== ""
    ? { file: search.file }
    : {};
}

export const Route = createFileRoute("/$env/secrets/$owner/$repo")({
  validateSearch: repoSearch,
  component: RepoPage,
});

function RepoPage() {
  const { owner, repo } = Route.useParams();
  const { file } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <SignedInPage>
      {/* a repository starts afresh: nothing of another's, such as a
          reseal it is running, carries over */}
      <RepoWorkspace
        key={`${owner}/${repo}`}
        owner={owner}
        repo={repo}
        selected={file}
        onSelect={(path) =>
          void navigate({ search: { file: path }, replace: true })
        }
      />
    </SignedInPage>
  );
}
