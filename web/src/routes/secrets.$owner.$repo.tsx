import { createFileRoute } from "@tanstack/react-router";
import { RepoWorkspace } from "@/components/repos/RepoWorkspace";
import { requireSignedIn, SignedInPage } from "@/lib/require-auth";

export interface RepoSearch {
  /** The chosen file's path. */
  file?: string;
}

export const Route = createFileRoute("/secrets/$owner/$repo")({
  validateSearch: (search: Record<string, unknown>): RepoSearch =>
    typeof search.file === "string" && search.file !== ""
      ? { file: search.file }
      : {},
  beforeLoad: requireSignedIn,
  component: RepoPage,
});

function RepoPage() {
  const { owner, repo } = Route.useParams();
  const { file } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <SignedInPage>
      <RepoWorkspace
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
