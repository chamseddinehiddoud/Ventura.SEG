#!/usr/bin/env bash
# Audit GitHub check-run/status context names before configuring required checks.
# This script is read-only: it does not modify Branch Protection or Rulesets.

set -euo pipefail

REPOSITORY="${1:-${GITHUB_REPOSITORY:-venturalabs-ai/ventura.SEG}}"
REF="${2:-main}"
shift $(( $# >= 2 ? 2 : $# ))
EXPECTED=("$@")

if [[ "$REPOSITORY" != */* ]]; then
  echo "usage: $0 OWNER/REPO [REF] [EXPECTED_CONTEXT ...]" >&2
  exit 2
fi

api_get() {
  local path="$1"
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh api -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" "$path"
    return
  fi
  if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo "error: authenticate with 'gh auth login' or export GITHUB_TOKEN" >&2
    exit 2
  fi
  curl --fail --silent --show-error \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com${path}"
}

CHECK_RUNS=$(api_get "/repos/${REPOSITORY}/commits/${REF}/check-runs?per_page=100")
STATUSES=$(api_get "/repos/${REPOSITORY}/commits/${REF}/status")

OBSERVED=$(CHECK_RUNS="$CHECK_RUNS" STATUSES="$STATUSES" python3 - <<'PY'
import json
import os

runs = json.loads(os.environ["CHECK_RUNS"])
statuses = json.loads(os.environ["STATUSES"])

names = {
    (run.get("name") or "").strip()
    for run in runs.get("check_runs", [])
    if (run.get("name") or "").strip()
}
names.update(
    (status.get("context") or "").strip()
    for status in statuses.get("statuses", [])
    if (status.get("context") or "").strip()
)
print("\n".join(sorted(names)))
PY
)

if [[ -z "$OBSERVED" ]]; then
  echo "No check contexts observed for ${REPOSITORY}@${REF}." >&2
  exit 1
fi

echo "Observed check contexts for ${REPOSITORY}@${REF}:"
printf '%s\n' "$OBSERVED" | sed 's/^/  - /'

# Optional expected contexts may be passed as positional arguments or as a
# newline-delimited EXPECTED_CHECKS environment variable.
if [[ -n "${EXPECTED_CHECKS:-}" ]]; then
  while IFS= read -r item; do
    [[ -n "$item" ]] && EXPECTED+=("$item")
  done <<< "$EXPECTED_CHECKS"
fi

if [[ ${#EXPECTED[@]} -eq 0 ]]; then
  echo "Audit-only mode: no expected contexts supplied; no protection change was made."
  exit 0
fi

missing=0
for expected in "${EXPECTED[@]}"; do
  if grep -Fxq -- "$expected" <<< "$OBSERVED"; then
    echo "OK   $expected"
  else
    echo "MISS $expected" >&2
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "Do not require missing contexts until the workflow names are corrected or observed on the target ref." >&2
  exit 1
fi

echo "All explicitly requested contexts were observed."
