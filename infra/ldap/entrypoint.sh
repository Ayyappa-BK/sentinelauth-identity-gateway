#!/bin/sh
set -eu
if [ ! -f /var/lib/ldap/data.mdb ]; then
 slapadd -f /etc/ldap/sentinel.conf -l /bootstrap.ldif
fi
exec slapd -f /etc/ldap/sentinel.conf -h ldap://0.0.0.0:1389 -d 256
