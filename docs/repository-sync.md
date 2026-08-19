# Repository Synchronization

WGDashboard-Guard is an independent enhancement repository based on the upstream WGDashboard project. Guard-specific history remains on `main`; bring upstream changes into it locally through a merge rather than rebasing or force-pushing published history.

## Remotes

```text
origin   https://github.com/Adsryen/WGDashboard-Guard.git
upstream https://github.com/donaldzou/WGDashboard.git
```

Confirm the topology before synchronizing:

```bash
git remote -v
```

## Daily upstream sync

Start on `main` with a clean worktree. Do not merge while changes are staged, unstaged, or untracked; commit them on the appropriate branch or stash them first.

```bash
git switch main
git status --short
```

When `git status --short` produces no output, fetch both remotes and inspect the incoming baseline before merging:

```bash
git fetch --prune upstream
git fetch --prune origin
git log --oneline --left-right --graph HEAD...upstream/main
git diff --stat HEAD..upstream/main
```

Merge the current upstream branch without rewriting Guard history:

```bash
git merge --no-ff upstream/main
```

Validate the merged result before publishing. Run checks appropriate to the imported changes; at minimum, check the diff and validate the container configuration. Run the documented network-policy integration suite when the merge affects that feature.

```bash
git diff --check
docker compose --file docker/compose.yaml config
./tests/integration/network-policy/run.sh
```

After the required validation succeeds, review the merge and push only `main`:

```bash
git status
git log --oneline --decorate -8
git push origin main
```

## Conflict recovery

Resolve conflicts only after reviewing both sides of each affected file. Stage each resolved file and continue the merge:

```bash
git status
git add <resolved-file>
git merge --continue
```

If the merge should not proceed, abandon the in-progress merge and return to the pre-merge `main` state:

```bash
git merge --abort
```

Do not use `git rebase`, `git push --force`, or a hard reset to synchronize upstream. If a conflict needs broader review, abort the merge, keep the worktree clean, and resolve it on a dedicated branch before retrying.
