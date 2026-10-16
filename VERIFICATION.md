# Verification record

Observed on October 15, 2026.

- Java 21 Maven build/package and 16 unit/security-policy tests passed.
- Eight real protocol integration tests passed against OpenLDAP 2.6.10 and MIT Kerberos on loopback. This included real LDAP binds, directory role resolution, AS/TGS ticket issuance, GSS-API/SPNEGO mutual authentication and replay rejection.
- Helm strict lint passed. Kubernetes schema validation results and CI results will be recorded after completion.
- The sandbox has no Docker engine. Native PostgreSQL initialization was attempted but its SysV shared-memory syscall was denied. Therefore full HTTP/session/audit integration is not yet locally verified; the Docker-backed GitHub Actions suite is the next check.
- No Kubernetes cluster deployment has been performed.

Unit test route-policy fixtures are distinct from the real LDAP/Kerberos integration tests. A default `mvn verify` explicitly skips external integration tests; use `scripts/integration.sh` to run them.
