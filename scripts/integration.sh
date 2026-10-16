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
sed 's/kdc = kdc:1088/kdc = localhost:1088/' infra/kerberos/krb5.conf > work/client-krb5.conf
docker compose cp kdc:/keytabs/http.keytab work/http.keytab
mvn -B verify -Pintegration -Dsentinel.protocol=true -Djava.security.krb5.conf="$PWD/work/client-krb5.conf"
# Both protocols must write successful audit rows to real PostgreSQL.
docker compose exec -T postgres psql -U sentinel -d sentinel -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
 IF (SELECT count(DISTINCT method) FROM auth_audit WHERE outcome='success') <> 2
 THEN RAISE EXCEPTION 'Missing successful protocol audits'; END IF;
 IF (SELECT count(*) FROM auth_audit WHERE length(trace_id)=32) < 1
 THEN RAISE EXCEPTION 'Missing audit trace correlation'; END IF;
 IF (SELECT count(*) FROM kerberos_replay) < 1
 THEN RAISE EXCEPTION 'Missing shared Kerberos replay ledger'; END IF;
END $$;
SQL
# Verify that OTLP traces actually reached the collector, not only that tracing is configured.
traced=false
for i in $(seq 1 15); do
 if docker compose logs otel 2>&1 | grep -Eq 'Traces.*spans'; then traced=true; break; fi
 sleep 2
done
[ "$traced" = true ] || { echo 'Collector did not receive traces' >&2; exit 1; }
python3 - <<'PYMETRICS'
import json,urllib.request,time
for attempt in range(15):
 with urllib.request.urlopen('http://localhost:9091/api/v1/query?query=up%7Bjob%3D%22sentinelauth%22%7D') as response:
  data=json.load(response)
 if any(row['value'][1]=='1' for row in data['data']['result']):
  print('Verified Prometheus scrape availability and OTLP trace delivery.')
  break
 time.sleep(2)
else:raise SystemExit('Prometheus did not scrape a healthy gateway')
PYMETRICS
