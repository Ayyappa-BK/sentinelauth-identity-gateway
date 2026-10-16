#!/usr/bin/env python3
"""Generate isolated local-only credentials. Never use this realm in production."""
from pathlib import Path
import base64,hashlib,secrets,os
root=Path(__file__).resolve().parent.parent
s=root/'.secrets';s.mkdir(mode=0o700,exist_ok=True)
for name in ['database_password','reader_password','alice_password','bob_password','kdc_master']:
 p=s/name
 if not p.exists():p.write_text(secrets.token_hex(24));p.chmod(0o600)
def ssha(name):
 salt=os.urandom(16);pw=(s/name).read_bytes()
 return '{SSHA}'+base64.b64encode(hashlib.sha1(pw+salt).digest()+salt).decode()
text=(root/'infra/ldap/bootstrap.ldif.template').read_text()
for token,name in [('READER_HASH','reader_password'),('ALICE_HASH','alice_password'),('BOB_HASH','bob_password')]:text=text.replace('{'+token+'}',ssha(name))
(s/'bootstrap.ldif').write_text(text);(s/'bootstrap.ldif').chmod(0o600)
env=root/'.env'
env.write_text('DATABASE_PASSWORD='+(s/'database_password').read_text()+'\nLDAP_BIND_PASSWORD='+(s/'reader_password').read_text()+'\n')
env.chmod(0o600)
print('Local credentials generated under .secrets (gitignored).')
