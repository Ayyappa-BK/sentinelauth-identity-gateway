#!/bin/sh
set -eu
if [ ! -f /var/lib/ldap/data.mdb ]; then
 slapadd -f /etc/ldap/sentinel.conf -l /bootstrap/bootstrap.ldif
 chown -R openldap:openldap /var/lib/ldap
fi
exec slapd -f /etc/ldap/sentinel.conf -h ldap://0.0.0.0:389 -u openldap -g openldap -d 256
