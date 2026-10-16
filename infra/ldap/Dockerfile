FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils && rm -rf /var/lib/apt/lists/* /var/lib/ldap/*
COPY infra/ldap/slapd.conf /etc/ldap/sentinel.conf
COPY infra/ldap/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["sh","/entrypoint.sh"]
