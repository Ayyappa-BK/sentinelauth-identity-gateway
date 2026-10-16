#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
gh auth status
owner=$(gh api user --jq .login)
if git ls-files | grep -E '(^|/)(\.env|\.secrets)(/|$)|\.keytab$|\.ccache$'; then
 echo 'Refusing to publish tracked credential files' >&2; exit 1
fi
gh repo create "$owner/sentinelauth-identity-gateway" --public --source=. --remote=origin --push
remote_head=$(git ls-remote origin refs/heads/main | cut -f1)
[ "$remote_head" = "$(git rev-parse HEAD)" ]
for path in pom.xml README.md compose.yaml src/main/java/io/sentinelauth/GatewayApplication.java src/test/java/io/sentinelauth/GatewayIT.java deploy/helm/sentinelauth/Chart.yaml deploy/kubernetes/sentinelauth.yaml; do
 gh api "repos/$owner/sentinelauth-identity-gateway/contents/$path" --jq .path
done
gh repo view "$owner/sentinelauth-identity-gateway" --json url,visibility
