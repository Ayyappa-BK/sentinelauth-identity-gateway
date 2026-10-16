FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server krb5-user curl jq ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10002 kdc && useradd -u 10002 -g kdc -M kdc && mkdir -p /keytabs /var/lib/krb5kdc && chown -R kdc:kdc /keytabs /var/lib/krb5kdc
USER 10002:10002
COPY infra/kerberos/krb5.conf /etc/krb5.conf
COPY infra/kerberos/kdc.conf /etc/krb5kdc/kdc.conf
COPY infra/kerberos/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["sh","/entrypoint.sh"]
