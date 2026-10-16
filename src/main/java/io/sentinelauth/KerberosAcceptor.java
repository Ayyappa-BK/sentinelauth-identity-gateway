package io.sentinelauth;

import jakarta.annotation.PreDestroy;
import java.nio.file.*;
import java.util.*;
import javax.security.auth.Subject;
import javax.security.auth.login.*;
import org.ietf.jgss.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
public class KerberosAcceptor {
  private final IdentityProperties p;
  private final LoginContext login;

  public KerberosAcceptor(IdentityProperties p) throws LoginException {
    this.p = p;
    if (!Files.isReadable(Path.of(p.keytab())))
      throw new IllegalArgumentException("Service keytab is not readable");
    var options =
        Map.<String, Object>of(
            "useKeyTab",
            "true",
            "keyTab",
            p.keytab(),
            "principal",
            p.servicePrincipal(),
            "storeKey",
            "true",
            "doNotPrompt",
            "true",
            "isInitiator",
            "false",
            "refreshKrb5Config",
            "true");
    var config =
        new Configuration() {
          public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            return new AppConfigurationEntry[] {
              new AppConfigurationEntry(
                  "com.sun.security.auth.module.Krb5LoginModule",
                  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                  options)
            };
          }
        };
    login = new LoginContext("sentinel", null, null, config);
    login.login();
  }

  public Result accept(String header) {
    try {
      if (header == null || !header.startsWith("Negotiate ") || header.length() > 65536)
        throw new IllegalArgumentException();
      var token = Base64.getDecoder().decode(header.substring(10));
      return Subject.callAs(
          login.getSubject(),
          () -> {
            GSSContext context = GSSManager.getInstance().createContext((GSSCredential) null);
            try {
              byte[] reply = context.acceptSecContext(token, 0, token.length);
              if (!context.isEstablished() || context.getAnonymityState())
                throw new GSSException(GSSException.FAILURE);
              String source = context.getSrcName().toString();
              String username = mapPrincipal(source, p.realm());
              return new Result(
                  username, reply == null ? null : Base64.getEncoder().encodeToString(reply));
            } finally {
              context.dispose();
            }
          });
    } catch (Exception ex) {
      throw new BadCredentialsException("Authentication failed");
    }
  }

  static String mapPrincipal(String principal, String realm) {
    String suffix = "@" + realm;
    if (!principal.endsWith(suffix)) throw new BadCredentialsException("Authentication failed");
    String uid = principal.substring(0, principal.length() - suffix.length());
    if (!uid.matches("[A-Za-z0-9._-]{1,64}"))
      throw new BadCredentialsException("Authentication failed");
    return uid;
  }

  @PreDestroy
  public void close() throws LoginException {
    login.logout();
  }

  public record Result(String username, String responseToken) {}
}
