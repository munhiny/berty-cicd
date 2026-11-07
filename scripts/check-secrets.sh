#!/usr/bin/env bash
# Pre-push secrets gate - canonical implementation (munhiny/berty-cicd scripts/check-secrets.sh).
#
# Blocks push if any file about to land on `main` (i.e. changed since
# branching from main, excluding env / .local / sealed-secret patterns)
# contains:
#   - Common secret markers (password=, api_key=, bearer <token>, etc.)
#   - PEM-encoded private cryptographic keys
#   - With --profile network: MAC addresses + psk= patterns (k8s-style)
#
# Usage:
#   check-secrets.sh [--profile code|network] [base-ref]
#   check-secrets.sh main                    # default code profile
#   check-secrets.sh --profile network main  # k8s/network-config profile
#
# A repository can call it from a thin wrapper script, passing the profile
# flag through:
#   exec path/to/berty-cicd/scripts/check-secrets.sh --profile network "$@"
#
# Exit codes:
#   0 - no violations, safe to push
#   1 - one or more violations found (prints offending file:line)
#   2 - misuse (no base ref, not in a git repo, etc.)

set -euo pipefail

PROFILE="code"

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)
      PROFILE="${2:-code}"
      shift 2
      ;;
    --profile=*)
      PROFILE="${1#--profile=}"
      shift
      ;;
    *)
      break
      ;;
  esac
done

case "$PROFILE" in
  code|network) ;;
  *)
    echo "check-secrets: unknown profile '$PROFILE' (expected: code | network)" >&2
    exit 2
    ;;
esac

BASE_REF="${1:-main}"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "check-secrets: not in a git repository" >&2
  exit 2
fi

if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  # Not a pass: a gate that cannot see its base has not checked anything.
  echo "check-secrets: base ref '$BASE_REF' not found (fetch it, or pass the right ref)" >&2
  exit 2
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" = "$BASE_REF" ]; then
  # On base itself - check the last commit's diff instead
  FILES=$(git diff --name-only HEAD~1..HEAD -- 2>/dev/null || true)
else
  FILES=$(git diff --name-only "$BASE_REF"...HEAD -- 2>/dev/null || true)
fi

# Exclude files that are either gitignored by convention or explicitly
# permitted to hold sensitive values (env files should be in .gitignore
# but scan-skip them defensively in case they slip into a diff).
FILES=$(printf "%s\n" "$FILES" \
  | grep -vE '\.env$|\.env\.[a-z.-]+$|\.local\.[a-z]+$|-secret\.ya?ml$|^secret.*\.ya?ml$' \
  || true)

if [ -z "$FILES" ]; then
  echo "check-secrets: no committed files changed vs $BASE_REF - OK"
  exit 0
fi

VIOLATIONS=0
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# Pattern definitions ---------------------------------------------------------
#
# code profile  - secret-assignment keys typical in app code / config files
# network profile - adds MAC addresses + psk= for WiFi pre-shared keys,
#                   broadens password-* prefix matching for switch/router cfg

if [ "$PROFILE" = "network" ]; then
  SECRET_KEYS='\b[a-z0-9_-]*(psk|password|passwd|api[_-]?key|access[_-]?key|secret[_-]?key|bearer[[:space:]]+[A-Za-z0-9_.-]+|client[_-]?secret|private[_-]?key|auth[_-]?token|jwt[_-]?secret)'
else
  SECRET_KEYS='\b[a-z0-9_-]*(password|passwd|api[_-]?key|access[_-]?key|secret[_-]?key|bearer[[:space:]]+[A-Za-z0-9_.-]+|client[_-]?secret|private[_-]?key|auth[_-]?token|jwt[_-]?secret)'
fi

# A value that is itself a secret-key name (an env var mapped to the setting
# named private_key) is a reference to a setting, not a secret.
# Literal <angle-token> placeholders. Do not write this as \<.*\>: in GNU ERE
# \< and \> are word boundaries, which matches every line and disables the check.
PLACEHOLDER_ALLOW='(example|placeholder|REPLACE_ME|TODO|FIXME|correct horse battery|[:=][[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*[,})]|[^[:alnum:]]pass:[[:alnum:]]|<[^>]+>|\{\{.*\}\}|\$[A-Z_]|process\.env\.|os\.getenv|[:=][[:space:]]*.?[a-z_]*(password|passwd|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|jwt[_-]?secret)[^a-z0-9]?[[:space:]]*[,}]?[[:space:]]*$)'
# Flag only literal values: a quoted string of 6+ characters, or a bare token
# of 8+ characters ending the assignment. Code that reads a secret from
# somewhere (profile.get(...), os.environ[...], settings.x) has '.', '(' or '['
# straight after the first word and is not flagged. Empty strings are not flagged.
SECRET_RE="${SECRET_KEYS}[\"']?[[:space:]]*[:=][[:space:]]*([\"'][^\"'[:space:]<{\$]{6,}|[A-Za-z0-9+/_-]{8,}([[:space:],;]|$))"

# Files whose "secrets" are fakes by nature: test files (fake credentials
# for fake servers) and the learnings log (quotes of error messages that
# name token files). Only the assignment check skips them; MAC addresses
# and PEM blocks are still scanned there.
assign_exempt() {
  case "$1" in
    tests/*|test/*|*/tests/*|*/test/*) return 0 ;;
  esac
  case "$(basename "$1")" in
    test_*|*_test.*|LEARNINGS.md) return 0 ;;
  esac
  return 1
}

for f in $FILES; do
  [ -f "$f" ] || continue

  # 1. MAC addresses (network profile only - k8s/network configs)
  if [ "$PROFILE" = "network" ]; then
    if grep -nHE '\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b' "$f" \
        | grep -vE '\b(00:00:00:00:00:00|ff:ff:ff:ff:ff:ff|FF:FF:FF:FF:FF:FF)\b' > "$TMP" \
        && [ -s "$TMP" ]; then
      echo "FAIL MAC address in $f:"
      sed 's/^/    /' "$TMP"
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  fi

  # 2. Secret assignment patterns
  #    Placeholder forms accepted: <anything>, {{anything}}, REPLACE_ME,
  #    $VAR, process.env.X, os.getenv('X').
  #    The allow-list is matched against the line content only, never the
  #    file path: a path containing "example" or "TODO" must not exempt
  #    every line in the file.
  if ! assign_exempt "$f" && grep -nE -i "$SECRET_RE" "$f" \
      | awk -v f="$f" -v re="$PLACEHOLDER_ALLOW" '{ c = $0; sub(/^[0-9]+:/, "", c); if (tolower(c) !~ tolower(re)) print f ":" $0 }' > "$TMP" \
      && [ -s "$TMP" ]; then
    echo "FAIL Potential secret assignment in $f:"
    sed 's/^/    /' "$TMP"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi

  # 3. PEM-encoded private keys
  if grep -nHE 'BEGIN (RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY' "$f" > "$TMP" \
      && [ -s "$TMP" ]; then
    echo "FAIL Private key block in $f:"
    sed 's/^/    /' "$TMP"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done

if [ $VIOLATIONS -gt 0 ]; then
  echo ""
  echo "FAIL $VIOLATIONS secret violation(s) in branch vs $BASE_REF - refusing to push."
  echo "  Fix:"
  echo "    - Move secret values to a .env file (ensure .env is gitignored)"
  echo "    - For k8s manifests: use Kubernetes Secrets via SOPS/sealed-secrets,"
  echo "      never plain Secret YAML with literal stringData:"
  echo "    - In code: read via process.env.X / os.getenv('X'), never hardcode"
  if [ "$PROFILE" = "network" ]; then
    echo "    - For device docs: rename to *.local.md (gitignored) and replace"
    echo "      committed references with placeholders like <device-mac>, <trusted-gw>"
  else
    echo "    - Replace committed references with placeholders like <api-key>"
    echo "      or {{.SecretValue}}"
  fi
  exit 1
fi

echo "OK No secrets detected in branch vs $BASE_REF (profile: $PROFILE)"
exit 0
