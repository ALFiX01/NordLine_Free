#!/usr/bin/env bash
set -euo pipefail

# Called immediately after creating the single subscription update commit.
build_base=$(git rev-parse HEAD^)

for attempt in 1 2 3; do
  echo "Push attempt $attempt/3"
  git fetch --no-tags origin refs/heads/main:refs/remotes/origin/main

  if ! git diff --quiet "$build_base" origin/main -- \
    build.py probe.py extract_keys.py validate.py .github; then
    echo "::notice::Publication skipped: generator changed during the build. Run the workflow again on current main."
    exit 0
  fi

  if ! git rebase origin/main; then
    git rebase --abort
    echo "::notice::Publication skipped: subscription conflict with current main. Remote files preserved; run the workflow again."
    exit 0
  fi

  if git push origin HEAD:refs/heads/main; then
    exit 0
  fi
done

echo "::error::Could not publish after 3 attempts. See the git push errors above."
exit 1
