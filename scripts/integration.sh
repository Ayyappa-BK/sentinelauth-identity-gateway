#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/init-local.py
docker compose up -d --build
ready=false
for i in $(seq 1 120); do
 if curl -fsS http://localhost:9090/actuator/health/readiness >/dev/null; then ready=true; break; fi
 sleep 2
done
if [ "$ready" != true ]; then docker compose logs --tail=100; exit 1; fi
mkdir -p work
sed 's/kdc = kdc:88/kdc = localhost:1088/' infra/kerberos/krb5.conf > work/client-krb5.conf
docker compose cp kdc:/keytabs/http.keytab work/http.keytab
mvn -B verify -Pintegration -Dsentinel.protocol=true -Djava.security.krb5.conf="$PWD/work/client-krb5.conf"
# Both protocols must write successful audit rows to real PostgreSQL.
docker compose exec -T postgres psql -U sentinel -d sentinel -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
 IF (SELECT count(DISTINCT method) FROM auth_audit WHERE outcome='success') <> 2
 THEN RAISE EXCEPTION 'Missing successful protocol audits'; END IF;
 IF (SELECT count(*) FROM kerberos_replay) < 1
 THEN RAISE EXCEPTION 'Missing shared Kerberos replay ledger'; END IF;
END $$;
SQL
