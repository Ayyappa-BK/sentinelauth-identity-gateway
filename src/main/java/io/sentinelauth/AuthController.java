package io.sentinelauth;
import java.util.*;
import java.util.function.Supplier;
import jakarta.servlet.http.*;
import io.micrometer.core.instrument.*;
import io.micrometer.observation.*;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.csrf.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.dao.DataAccessException;
@RestController
@RequestMapping("/api/auth")
public class AuthController {
 private final LdapDirectory directory;private final KerberosAcceptor kerberos;private final AuditTrail audit;
 private final MeterRegistry metrics;private final ObservationRegistry observations;
 private final AttemptLimiter limiter;private final SecurityContextRepository repository;
 public AuthController(LdapDirectory directory,KerberosAcceptor kerberos,AuditTrail audit,MeterRegistry metrics,
  ObservationRegistry observations,AttemptLimiter limiter,SecurityContextRepository repository){
  this.directory=directory;this.kerberos=kerberos;this.audit=audit;this.metrics=metrics;
  this.observations=observations;this.limiter=limiter;this.repository=repository;
 }
 @GetMapping("/csrf") public Map<String,String> csrf(CsrfToken token){return Map.of("token",token.getToken(),"headerName",token.getHeaderName());}
 @PostMapping(value="/ldap",consumes=MediaType.APPLICATION_FORM_URLENCODED_VALUE)
 public ResponseEntity<?> ldap(@RequestParam String username,@RequestParam String password,HttpServletRequest q,HttpServletResponse s){
  return authenticate("ldap",username,q,s,()->new Accepted(directory.authenticate(username,password),null));
 }
 @PostMapping("/kerberos") public ResponseEntity<?> kerberos(@RequestHeader(value="Authorization",required=false)String header,HttpServletRequest q,HttpServletResponse s){
  return authenticate("kerberos",null,q,s,()->{var result=kerberos.accept(header);
   var identity=directory.resolve(result.username());audit.claimTicket(header);
   return new Accepted(identity,result.responseToken());});
 }
 private ResponseEntity<?> authenticate(String method,String user,HttpServletRequest q,HttpServletResponse s,Supplier<Accepted> operation){
  var timer=io.micrometer.core.instrument.Timer.start(metrics);
  var observation=Observation.start("sentinel.authentication",observations).lowCardinalityKeyValue("method",method);
  String outcome="unavailable";
  try(var scope=observation.openScope()){
   if(!limiter.allow(q.getRemoteAddr())){
    outcome="throttled";audit.record(method,outcome,user,q.getRemoteAddr());
    return ResponseEntity.status(429).header("Retry-After","60").body(Map.of("error","too_many_attempts"));
   }
   var accepted=operation.get();
   audit.record(method,"success",accepted.identity().username(),q.getRemoteAddr());
   var auth=UsernamePasswordAuthenticationToken.authenticated(accepted.identity().username(),null,accepted.identity().authorities());
   new ChangeSessionIdAuthenticationStrategy().onAuthentication(auth,q,s);
   new CsrfAuthenticationStrategy(new HttpSessionCsrfTokenRepository()).onAuthentication(auth,q,s);
   var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(auth);
   SecurityContextHolder.setContext(context);repository.saveContext(context,q,s);
   if(accepted.responseToken()!=null)s.setHeader("WWW-Authenticate","Negotiate "+accepted.responseToken());
   outcome="success";
   return ResponseEntity.ok(Map.of("username",accepted.identity().username(),"roles",accepted.identity().roles()));
  }catch(BadCredentialsException ex){
   invalidate(q);outcome="failure";
   try{audit.record(method,outcome,user,q.getRemoteAddr());}catch(DataAccessException unavailable){return ResponseEntity.status(503).body(Map.of("error","authentication_unavailable"));}
   var response=ResponseEntity.status(401);if(method.equals("kerberos"))response.header("WWW-Authenticate","Negotiate");
   return response.body(Map.of("error","authentication_failed"));
  }catch(AuthenticationServiceException|DataAccessException ex){
   invalidate(q);observation.error(ex);
   return ResponseEntity.status(503).body(Map.of("error","authentication_unavailable"));
  }finally{
   metrics.counter("sentinel.auth.attempts","method",method,"outcome",outcome).increment();
   timer.stop(metrics.timer("sentinel.auth.latency","method",method));observation.stop();
  }
 }
 private void invalidate(HttpServletRequest request){SecurityContextHolder.clearContext();var session=request.getSession(false);if(session!=null)session.invalidate();}
 private record Accepted(DirectoryIdentity identity,String responseToken){}
}
