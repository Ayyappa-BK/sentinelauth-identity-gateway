#!/bin/sh
set -eu
if [ ! -f /var/lib/krb5kdc/principal ]; then
 kdb5_util create -s -P "$(cat /run/secrets/kdc_master)"
 kadmin.local -q "addprinc -pw $(cat /run/secrets/alice_password) alice@SENTINEL.TEST"
 kadmin.local -q 'addprinc -randkey HTTP/gateway@SENTINEL.TEST'
 kadmin.local -q 'ktadd -k /keytabs/http.keytab HTTP/gateway@SENTINEL.TEST'
 chmod 0444 /keytabs/http.keytab
fi
exec krb5kdc -n
