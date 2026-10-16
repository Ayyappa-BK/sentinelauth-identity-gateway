-- Run as schema owner after migrations. Create sentinel_runtime separately using your secret manager.
-- Keep schema ownership and DDL permissions out of the runtime account.
GRANT CONNECT ON DATABASE sentinel TO sentinel_runtime;
GRANT USAGE ON SCHEMA public TO sentinel_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON spring_session,spring_session_attributes TO sentinel_runtime;
GRANT INSERT ON auth_audit TO sentinel_runtime;
GRANT USAGE ON SEQUENCE auth_audit_id_seq TO sentinel_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT INSERT ON kerberos_replay TO sentinel_runtime;
