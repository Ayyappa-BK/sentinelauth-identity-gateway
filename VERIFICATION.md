# Verification record

Verified October 15, 2026 (America/Chicago). Tested source commit: `793f337861fae477c04ed896938d89a6193fa0f5`.

[Successful GitHub Actions run](https://github.com/Ayyappa-BK/sentinelauth-identity-gateway/actions/runs/38831394555)

## Executed checks

- **41 distinct JUnit tests passed:** 23 unit/security-policy tests, eight real LDAP/Kerberos protocol tests, and ten real HTTP end-to-end tests. The integration invocation ran all external tests with no skips. The preceding default `mvn verify` intentionally skipped the 18 external tests before their services started.
- The complete Docker Compose stack built and ran on the Linux GitHub Actions runner with PostgreSQL 17, real OpenLDAP and an MIT Kerberos KDC. Both identity fixtures ran as nonroot users. Application Java version: 21; Spring Boot: 3.5.16.
- Real LDAP user binds, explicit USER/ADMIN directory groups, valid users with no roles, invalid passwords, unknown users, empty passwords and filter-injection input were exercised.
- Real KDC AS/TGS exchanges, SPNEGO service-ticket acceptance, mutual authentication, wrong Kerberos passwords, malformed tokens and replay rejection were exercised. No substitute authentication provider was used in these tests.
- HTTP checks passed for CSRF enforcement, anonymous denial, session ID rotation, old-cookie invalidation, logout, USER/admin separation and least-privilege defaults.
- PostgreSQL assertions confirmed successful audit records from both protocols, correlated trace IDs, and a shared raw-token replay ledger entry.
- Actual OTLP trace delivery to the collector and actual successful Prometheus scraping were asserted, in addition to metric names/outcomes and HTTP health checks.
- Reproducible curl scenarios passed for successful LDAP login, authenticated identity access, denied admin access and failed credentials.
- Strict Helm lint, rendered manifest comparison, Compose validation, shell syntax validation and Docker image build passed in CI. Locally, kubeconform validated all five default Kubernetes resources and all six resources with optional TLS ingress enabled.
- Trivy filesystem/configuration/dependency and runtime-image gates passed. **Two package/version-specific Spring MVC applicability exceptions remain**, displayed in the scan output and expiring November 15, 2026. See `.trivyignore.yaml` and [SECURITY.md](SECURITY.md). This is not a claim of zero dependency findings. The PR-only dependency-review job was correctly skipped for this push.

## Local environment and deployment limits

On the local macOS sandbox, 31 tests passed: the 23 unit/policy tests plus eight real protocol tests using a locally built OpenLDAP 2.6.10 server and native MIT Kerberos KDC. The sandbox has no Docker engine, and native PostgreSQL initialization was blocked by its SysV shared-memory syscall restriction. Full HTTP/PostgreSQL integration was therefore verified in Docker Compose on the CI runner, rather than on this macOS host. Local reproduction requires the README's Docker, Java 21 and Maven prerequisites.

No Kubernetes cluster deployment or production rollout was performed. The chart still needs real infrastructure endpoints, CA trust, secrets, a published image, DNS/SPN registration and ingress TLS before installation. The development KDC and directory must not be used as production identity infrastructure.

Documentation-only commits after the tested source commit do not change application or deployment behavior. CI ignores Markdown-only updates.
