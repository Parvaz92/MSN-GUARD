#!/usr/bin/env bash
# Keep the Yekta fork aligned with MSN-GUARD while preserving Yekta-only files.
# Intended to run from a scheduled GitHub Actions job or a local cron job.
set -euo pipefail

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/mbm110/MSN-GUARD.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-master}"
WORKTREE="${WORKTREE:-.upstream-sync-worktree}"

cleanup() { git worktree remove --force "$WORKTREE" 2>/dev/null || true; }
trap cleanup EXIT

git fetch --no-tags "$UPSTREAM_URL" "$UPSTREAM_BRANCH"
UPSTREAM_REF="FETCH_HEAD"

# Never overwrite Yekta's legal notice, branding, social links, or build-time
# rebrand layer. Everything else follows the upstream source tree.
git worktree add --detach "$WORKTREE" HEAD
cd "$WORKTREE"
git remote add upstream "$UPSTREAM_URL" 2>/dev/null || true
git fetch --no-tags upstream "$UPSTREAM_BRANCH"

git checkout -B upstream-sync HEAD

git merge --no-edit --no-commit "upstream/$UPSTREAM_BRANCH" || {
  echo "Upstream changes conflict with Yekta customizations. Resolve manually:" >&2
  git diff --name-only --diff-filter=U >&2
  exit 2
}

# Re-apply fork-owned files after the upstream merge.
git checkout HEAD -- NOTICE.md README.md README.en.md tools/rebrand.sh tools/sync-upstream.sh branding 2>/dev/null || true

git add -A
git commit -m "Sync upstream MSN-GUARD into Yekta VPN" || echo "Already up to date"
git push origin upstream-sync:master
