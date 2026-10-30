#!/bin/sh
# Fails if the repository contains likely secrets or personal data.
# Run before every commit:  sh tools/check-no-secrets.sh
# Only the standard tools grep and find are used. No network access.
set -u
cd "$(dirname "$0")/.." || exit 2
fail=0

scan() {  # $1 = description, $2 = extended regex
  hits=$(grep -rInE --exclude-dir=.git --exclude=check-no-secrets.sh -e "$2" . 2>/dev/null)
  if [ -n "$hits" ]; then
    echo "FAIL: $1"; echo "$hits" | head -20; echo; fail=1
  fi
}

scan "private key block"        '-----BEGIN [A-Z ]*PRIVATE KEY-----'
scan "PGP private key"          'BEGIN PGP PRIVATE KEY'
scan "email address"            '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
scan "GitHub token"             '(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}'
scan "AWS access key"           'AKIA[0-9A-Z]{16}'
scan "generic secret assignment" '(api[_-]?key|secret|password|passwd|token)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{8,}'
scan "Slack/Discord token"      '(xox[abpr]-[A-Za-z0-9-]{10,}|[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})'
scan "BIP-39-like word run (possible seed)" '^[[:space:]]*([a-z]{3,8}[ ,]+){11,23}[a-z]{3,8}[[:space:]]*$'
scan "home-directory path"      '(/Users/|/home/|C:\\Users\\)[A-Za-z0-9._-]+'
scan "claude.ai session or artifact link" 'claude\.ai/(code|artifact|chat)'

for f in $(find . -path ./.git -prune -o -type f \( -name '*.pem' -o -name '*.key' -o -name '.env*' -o -name '*.kdbx' -o -name 'wallet*.dat' \) -print); do
  echo "FAIL: forbidden file $f"; fail=1
done

if [ "$fail" -eq 0 ]; then echo "OK: no secrets or personal data patterns found."; fi
exit "$fail"
