# supSec Scan Report

**Target:** `.`

**Findings:** 9

| Severity | File | Line | Rule | Message |
|---|---|---|---|---|
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 17 | GHA-002 | Action 'actions/checkout' pinned to mutable tag 'v4' — supply chain risk |
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 19 | GHA-002 | Action 'actions/setup-python' pinned to mutable tag 'v5' — supply chain risk |
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 24 | GHA-002 | Action 'astral-sh/setup-uv' pinned to mutable tag 'v4' — supply chain risk |
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 43 | GHA-002 | Action 'actions/checkout' pinned to mutable tag 'v4' — supply chain risk |
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 45 | GHA-002 | Action 'actions/setup-python' pinned to mutable tag 'v5' — supply chain risk |
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 50 | GHA-002 | Action 'astral-sh/setup-uv' pinned to mutable tag 'v4' — supply chain risk |
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 63 | GHA-002 | Action 'github/codeql-action/upload-sarif' pinned to mutable tag 'v3' — supply chain risk |
| 🟡 MEDIUM | `.github/workflows/ci.yml` | 70 | GHA-002 | Action 'actions/upload-artifact' pinned to mutable tag 'v4' — supply chain risk |
| ℹ️ INFO | `Dockerfile` | 1 | DOCKER-011 | No HEALTHCHECK instruction — orchestrator cannot detect unhealthy containers |

## Remediations

### GHA-002: Action 'actions/checkout' pinned to mutable tag 'v4' — supply chain risk

**Fix:** Pin to a full SHA: uses: actions/checkout@<sha256>

**Reference:** https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

### DOCKER-011: No HEALTHCHECK instruction — orchestrator cannot detect unhealthy containers

**Fix:** Add HEALTHCHECK CMD to verify the service is responding

---

**PASSED** — no blocking issues.
