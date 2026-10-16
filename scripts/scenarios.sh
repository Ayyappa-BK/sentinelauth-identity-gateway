#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsS -c "$tmp/cookies" http://localhost:8080/api/auth/csrf > "$tmp/csrf.json"
token=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["token"])' "$tmp/csrf.json")
# Password is read from a file; it is never printed or embedded in process arguments.
status=$(curl -sS -o "$tmp/login" -w '%{http_code}' -b "$tmp/cookies" -c "$tmp/cookies" -H "X-CSRF-TOKEN: $token" --data-urlencode username=alice --data-urlencode password@.secrets/alice_password http://localhost:8080/api/auth/ldap)
[ "$status" = 200 ] || { cat "$tmp/login"; exit 1; }
cat "$tmp/login"
curl -fsS -b "$tmp/cookies" http://localhost:8080/api/me
status=$(curl -sS -o "$tmp/admin" -w '%{http_code}' -b "$tmp/cookies" http://localhost:8080/api/admin/status)
[ "$status" = 403 ]
curl -fsS -b "$tmp/cookies" -c "$tmp/cookies" http://localhost:8080/api/auth/csrf > "$tmp/csrf.json"
token=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["token"])' "$tmp/csrf.json")
status=$(curl -sS -o "$tmp/failure" -w '%{http_code}' -b "$tmp/cookies" -H "X-CSRF-TOKEN: $token" -d 'username=alice&password=wrong' http://localhost:8080/api/auth/ldap)
[ "$status" = 401 ]
cat "$tmp/failure"
printf '\nVerified LDAP success, USER authorization, ADMIN denial and credential failure.\n'
