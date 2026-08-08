# Scripts operacionais — Ventura.SEG

## `validate_check_names.sh`

Valida se os **nomes dos status checks** (contexts) usados em branch protection já apareceram no GitHub Actions para o ref informado.

### Por que existe

Branch protection só funciona de forma confiável com contexts que o GitHub **já observou** em algum commit. Este script evita aplicar regras com nomes errados ou checks que ainda nunca rodaram.

### Autenticação

```bash
gh auth login
# ou
export GITHUB_TOKEN=...   # nunca commitar o token
```

### Uso

```bash
chmod +x scripts/validate_check_names.sh

# Fase mínima (padrão)
./scripts/validate_check_names.sh main

# Contra o HEAD de um PR
./scripts/validate_check_names.sh <commit-sha>

# Fase FULL (CI + Security + CodeQL)
FULL=1 ./scripts/validate_check_names.sh main
```

### Ordem recomendada de branch protection

1. **Mínima agora** — 1 job de CI + `Analyze (...)` por repo  
2. Abrir **1–2 PRs verdes** e confirmar checks na UI  
3. Rodar este script até exit 0  
4. **FULL** — incluir Policy integrity, Dependency audit, Secrets scan, etc.  
5. Ajustar em **Settings → Branches** se algum context divergir

### Repos cobertos (mínima)

| Repo | Contexts |
|------|----------|
| Ventura.SEG | `Tests and coverage (Python 3.12)`, `Analyze (Python)` |
| ventura-sec | `test`, `Analyze (Python)` |
| ventura-aifree | `quality`, `Analyze (JavaScript/TypeScript)` |
| ai-animation-academy | `Analyze (JavaScript/TypeScript)` |

### Exit codes

| Code | Significado |
|------|-------------|
| 0 | Todos os contexts esperados foram observados |
| 1 | Há MISS ou nenhum check no ref |
