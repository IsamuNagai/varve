#!/bin/sh
# Fails if the repository contains likely secrets or personal data.
# Run before every commit:   sh tools/check-no-secrets.sh
# Also scan all git history:  sh tools/check-no-secrets.sh --history
# Only standard tools (grep, find, git). No network access.
# This is one extra layer, not a replacement for GitHub secret scanning or a
# dedicated history scanner before releases (audit L-03).
set -u
cd "$(dirname "$0")/.." || exit 2
fail=0

# The only e-mail addresses allowed anywhere (commit trailers / noreply).
ALLOW_EMAIL='(noreply@anthropic\.com|[0-9]+\+IsamuNagai@users\.noreply\.github\.com)'

PATTERNS='private key block|-----BEGIN [A-Z ]*PRIVATE KEY-----
PGP private key|BEGIN PGP PRIVATE KEY
email address|[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
GitHub token|(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}
AWS access key|AKIA[0-9A-Z]{16}
generic secret assignment|(api[_-]?key|secret|password|passwd|token)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{8,}
Slack/Discord token|(xox[abpr]-[A-Za-z0-9-]{10,}|[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})
BIP-39-like word run (possible seed)|^[[:space:]+-]*([a-z]{3,8}[ ,]+){11,23}[a-z]{3,8}[[:space:]]*$
home-directory path|(/Users/|/home/|C:\\Users\\)[A-Za-z0-9._-]+
claude.ai session or artifact link|claude\.ai/(code|artifact|chat)'

report() {  # $1 = description, $2 = hits
  if [ -n "$2" ]; then echo "FAIL: $1"; echo "$2" | head -20; echo; fail=1; fi
}

# Every pattern must compile; a broken regex must never pass silently.
printf "%s\n" "$PATTERNS" | while IFS='|' read -r desc re; do
  echo | grep -E -e "$re" >/dev/null 2>&1; [ $? -le 1 ] || { echo "BROKEN PATTERN: $desc"; exit 3; }
done || exit 3

# Files that would be committed: tracked plus untracked-but-not-ignored (NUL-safe).
files0() { git ls-files -z -co --exclude-standard -- . ':(exclude)tools/check-no-secrets.sh'; }

scan_tree() {
  printf "%s\n" "$PATTERNS" | while IFS='|' read -r desc re; do
    # Text files: show matching lines.
    hits=$(files0 | xargs -0 grep -InE -e "$re" -- 2>/dev/null | grep -vE "$ALLOW_EMAIL")
    # Binary files (images etc.): list files whose raw bytes match.
    bin=$(files0 | xargs -0 grep -IL -e '' -- 2>/dev/null | while IFS= read -r f; do
            [ -s "$f" ] && LC_ALL=C grep -aqE -e "$re" -- "$f" 2>/dev/null && echo "binary: $f"; done)
    [ -n "$hits$bin" ] && { echo "FAIL: $desc"; printf '%s\n%s\n' "$hits" "$bin" | sed '/^$/d' | head -20; echo; echo x >> "$TMPF"; }
  done
}

TMPF=$(mktemp) || exit 2
trap 'rm -f "$TMPF"' EXIT
scan_tree
[ -s "$TMPF" ] && fail=1

# Forbidden file types (handles any file name safely).
forbidden=$(files0 | tr '\0' '\n' | grep -E '(\.pem|\.key|\.kdbx)$|(^|/)\.env|(^|/)wallet[^/]*\.dat$|(^|/)id_(rsa|ed25519)')
report "forbidden file type" "$forbidden"

if [ "${1:-}" = "--history" ]; then
  : > "$TMPF"
  printf "%s\n" "$PATTERNS" | while IFS='|' read -r desc re; do
    hits=$(git log --all -p --format='commit %H%n%B' -- . ':(exclude)tools/check-no-secrets.sh' 2>/dev/null \
           | LC_ALL=C grep -aE -e "$re" | grep -vE "$ALLOW_EMAIL" | head -20)
    [ -n "$hits" ] && { echo "FAIL (history): $desc"; echo "$hits"; echo; echo x >> "$TMPF"; }
  done
  [ -s "$TMPF" ] && fail=1
  # Author/committer identities must be the pen name only.
  ids=$(git log --all --format='%an <%ae>%n%cn <%ce>' | sort -u | grep -vE "^(Isamu Nagai <$ALLOW_EMAIL>|GitHub <noreply@github\.com>)$")
  report "unexpected commit identity in history" "$ids"
fi

if [ "$fail" -eq 0 ]; then echo "OK: no secrets or personal data patterns found."; fi
exit "$fail"
