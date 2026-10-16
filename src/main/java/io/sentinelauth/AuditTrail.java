package io.sentinelauth;
import io.micrometer.tracing.Tracer;
import org.slf4j.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
@Service
public class AuditTrail {
 private static final Logger log=LoggerFactory.getLogger(AuditTrail.class);
 private final JdbcTemplate jdbc;private final Tracer tracer;
 public AuditTrail(JdbcTemplate jdbc,Tracer tracer){this.jdbc=jdbc;this.tracer=tracer;}
 // A shared raw-token ledger supplements the JVM Kerberos replay cache.
 public void claimTicket(String header){
  try {
   var digest=java.security.MessageDigest.getInstance("SHA-256").digest(java.util.Base64.getDecoder().decode(header.substring(10)));
   String hash=java.util.HexFormat.of().formatHex(digest);
   int inserted=jdbc.update("insert into kerberos_replay(token_hash) values (?) on conflict do nothing",hash);
   if(inserted!=1)throw new org.springframework.security.authentication.BadCredentialsException("Authentication failed");
  }catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
 }
 public void record(String method,String outcome,String user,String ip){
  String safe=user!=null && user.matches("[A-Za-z0-9._-]{1,64}")?user:"unknown";
  String trace=tracer.currentSpan()==null?"":tracer.currentSpan().context().traceId();
  jdbc.update("insert into auth_audit(method,outcome,subject,source_address,trace_id) values (?,?,?,?,?)",method,outcome,safe,ip,trace);
  log.atInfo().addKeyValue("event","authentication").addKeyValue("method",method)
   .addKeyValue("outcome",outcome).addKeyValue("subject",safe).addKeyValue("source_address",ip)
   .addKeyValue("trace_id",trace).log("Authentication decision");
 }
}
