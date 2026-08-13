#!/usr/bin/env bash
# Bootstraps (or re-syncs) the label set this repo's workflow depends on.
# Idempotent: safe to re-run after editing. Requires `gh auth login`.
#
# Usage: .github/labels.sh [owner/repo]   (defaults to the current repo)
set -euo pipefail

repo_flag=""
if [ "${1-}" != "" ]; then
  repo_flag="$1"
fi

gh_label() {
  if [ -n "$repo_flag" ]; then
    gh label create "$1" --color "$2" --description "$3" --force --repo "$repo_flag"
  else
    gh label create "$1" --color "$2" --description "$3" --force
  fi
}

# name|color|description
labels=(
  "bug|d73a4a|Crash, wrong exit code, or other non-detection defect"
  "false-positive|e4e669|A rule flagged code that isn't actually vulnerable"
  "false-negative|e4e669|A real misconfiguration wasn't caught"
  "new-rule|0e8a16|Request for a brand-new detection rule"
  "enhancement|a2eeef|Improvement to something that already exists"
  "documentation|0075ca|README, rule docs, or other documentation"
  "question|d876e3|Usage question, not a confirmed bug or request"
  "good first issue|7057ff|Good for a first-time contributor"
  "help wanted|008672|Maintainer is looking for help on this one"
  "duplicate|cfd3d7|Already tracked elsewhere"
  "wontfix|ffffff|Will not be worked on"
  "dependencies|0366d6|Dependabot version bumps"
)

for entry in "${labels[@]}"; do
  IFS='|' read -r name color desc <<<"$entry"
  gh_label "$name" "$color" "$desc"
done
