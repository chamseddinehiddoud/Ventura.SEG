#!/usr/bin/env bash
# validate_check_names.sh
#
# Valida se os nomes (contexts) esperados para branch protection já
# apareceram como check-runs/status no ref informado.
#
# Auth (nunca hardcode token):
#   gh auth login
#   ou: export GITHUB_TOKEN=...
#
# Uso:
#   ./scripts/validate_check_names.sh              # ref=main
#   ./scripts/validate_check_names.sh main
#   ./scripts/validate_check_names.sh <commit-sha>
#
# Exit 0 = todos os contexts esperados foram observados
# Exit 1 = há MISS ou nenhum check no ref

set -euo pipefail

ORG="venturalabs-ai"
REF="${1:-main}"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  AUTH_HEADER="Authorization: Bearer $(gh auth token)"
elif [[ -n "${GITHUB_TOKEN:-}" ]]; then
  AUTH_HEADER="Authorization: Bearer ${GITHUB_TOKEN}"
else
  echo "Erro: autentique com 'gh auth login' ou exporte GITHUB_TOKEN"
  exit 1
fi

API="https://api.github.com"
ACCEPT="Accept: application/vnd.github+json"
API_VERSION="X-GitHub-Api-Version: 2022-11-28"

# Formato: repo|context1|context2|...
# Fase mínima (1 CI + CodeQL). Amplie para FULL quando estável.
EXPECTED_ENTRIES=(
  "Ventura.SEG|Tests and coverage (Python 3.12)|Analyze (Python)"
  "ventura-sec|test|Analyze (Python)"
  "ventura-aifree|quality|Analyze (JavaScript/TypeScript)"
  "ai-animation-academy|Analyze (JavaScript/TypeScript)"
)

# Contexts adicionais da fase FULL (só reportados se FULL=1)
FULL_ENTRIES=(
  "Ventura.SEG|Lint YAML policies|Tests and coverage (Python 3.11)|Secrets scan|Policy integrity|Dependency audit"
  "ventura-sec|Dependency audit"
)

fail=0
mode="minimal"
if [[ "${FULL:-0}" == "1" ]]; then
  mode="full"
fi

echo "Validando check contexts (mode=${mode}, ref=${REF})"
echo

validate_repo() {
  local REPO="$1"
  shift
  local -a WANT=("$@")

  echo "=== ${ORG}/${REPO} @ ${REF} ==="

  local RUNS STATUSES
  RUNS=$(curl -sS \
    -H "${AUTH_HEADER}" -H "${ACCEPT}" -H "${API_VERSION}" \
    "${API}/repos/${ORG}/${REPO}/commits/${REF}/check-runs?per_page=100") || RUNS='{}'

  STATUSES=$(curl -sS \
    -H "${AUTH_HEADER}" -H "${ACCEPT}" -H "${API_VERSION}" \
    "${API}/repos/${ORG}/${REPO}/commits/${REF}/status") || STATUSES='{}'

  local ALL
  ALL=$(REPO_JSON_RUNS="$RUNS" REPO_JSON_STATUSES="$STATUSES" python3 - <<'PY'
import json, os

runs = json.loads(os.environ.get("REPO_JSON_RUNS") or "{}")
statuses = json.loads(os.environ.get("REPO_JSON_STATUSES") or "{}")

names = set()
for c in runs.get("check_runs") or []:
    n = (c.get("name") or "").strip()
    if n:
        names.add(n)
for s in statuses.get("statuses") or []:
    n = (s.get("context") or "").strip()
    if n:
        names.add(n)

for n in sorted(names):
    print(n)
PY
)

  if [[ -z "${ALL}" ]]; then
    echo "  (nenhum check neste ref — rode CI/CodeQL em um PR primeiro)"
    fail=1
    echo
    return
  fi

  echo "  Checks observados:"
  echo "${ALL}" | sed 's/^/    - /'

  local c
  for c in "${WANT[@]}"; do
    if echo "${ALL}" | grep -Fxq "${c}"; then
      echo "  OK   ${c}"
    else
      echo "  MISS ${c}"
      echo "${ALL}" | grep -iE 'analyze|test|quality|codeql|audit|lint|secret|policy' \
        | sed 's/^/       candidate: /' || true
      fail=1
    fi
  done
  echo
}

for entry in "${EXPECTED_ENTRIES[@]}"; do
  REPO="${entry%%|*}"
  REST="${entry#*|}"
  IFS='|' read -r -a WANT <<< "${REST}"
  validate_repo "${REPO}" "${WANT[@]}"
done

if [[ "${FULL}" == "1" ]]; then
  echo "--- contexts adicionais (FULL) ---"
  echo
  for entry in "${FULL_ENTRIES[@]}"; do
    REPO="${entry%%|*}"
    REST="${entry#*|}"
    IFS='|' read -r -a WANT <<< "${REST}"
    validate_repo "${REPO}" "${WANT[@]}"
  done
fi

if [[ "${fail}" -ne 0 ]]; then
  echo "Resultado: divergências encontradas."
  echo "Não aplique branch protection FULL até corrigir os MISS."
  exit 1
fi

echo "Resultado: todos os contexts esperados (${mode}) foram observados."
echo "Ordem sugerida: mínima agora → 1–2 PRs verdes → full (FULL=1)."
