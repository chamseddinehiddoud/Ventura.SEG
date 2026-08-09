# Operational scripts — Ventura.SEG

## `validate_check_names.sh`

Read-only auditor for GitHub required-check context names. It queries the check-runs and commit statuses that GitHub has actually observed for a repository/ref before an administrator configures Branch Protection or Rulesets.

The script **does not modify repository settings** and intentionally contains no hardcoded list of repositories or required contexts.

### Authentication

```bash
gh auth login
# or
export GITHUB_TOKEN=...
```

Never commit a token.

### Discover the real contexts first

```bash
chmod +x scripts/validate_check_names.sh
./scripts/validate_check_names.sh venturalabs-ai/ventura.SEG main
./scripts/validate_check_names.sh venturalabs-ai/ventura-aifree main
./scripts/validate_check_names.sh venturalabs-ai/Ventura.ai-animation main
```

With no expected contexts supplied, the command lists what GitHub currently observes and exits successfully when at least one context exists.

### Validate a proposed required-check set

Pass exact names as arguments:

```bash
./scripts/validate_check_names.sh \
  venturalabs-ai/ventura.SEG \
  main \
  "Tests and coverage (Python 3.12)" \
  "Analyze (Python)"
```

Or use a newline-delimited environment variable:

```bash
EXPECTED_CHECKS=$'Tests and coverage (Python 3.12)\nAnalyze (Python)' \
  ./scripts/validate_check_names.sh venturalabs-ai/ventura.SEG main
```

### Exit codes

- `0`: contexts were observed; when expectations were supplied, every expected context matched exactly.
- `1`: the ref has no observed checks or at least one expected context is missing.
- `2`: invalid usage or missing authentication.

### Safe operating sequence

1. Run the relevant workflows on `main` or a representative PR head.
2. Use audit-only mode to capture the exact check-run names GitHub reports.
3. Validate the proposed required contexts explicitly.
4. Only then configure Branch Protection/Rulesets in GitHub settings.
5. Re-run this auditor after workflow renames so stale required contexts are detected before they block merges.

Repository settings remain an administrator action; this script only validates evidence.
