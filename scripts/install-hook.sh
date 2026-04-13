#!/usr/bin/env bash
# Install supSec as a git pre-commit hook in the current repo.
set -euo pipefail

if [ ! -d .git ]; then
  echo "Error: not a git repository. Run from the repo root."
  exit 1
fi

HOOK=".git/hooks/pre-commit"

cat > "$HOOK" << 'HOOK_EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "=== supSec pre-commit scan ==="

if command -v supsec &>/dev/null; then
    supsec scan . --fail-on high
elif command -v poetry &>/dev/null && [ -f pyproject.toml ]; then
    poetry run supsec scan . --fail-on high
else
    echo "Warning: supsec not found. Skipping scan."
    exit 0
fi
HOOK_EOF

chmod +x "$HOOK"
echo "Pre-commit hook installed: $HOOK"
