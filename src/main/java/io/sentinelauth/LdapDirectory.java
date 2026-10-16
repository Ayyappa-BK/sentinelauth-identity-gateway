package io.sentinelauth;

import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
public class LdapDirectory {
  private final IdentityProperties p;

  public LdapDirectory(IdentityProperties p) {
    this.p = p;
    var endpoint = java.net.URI.create(p.ldapUrl());
    boolean tls = "ldaps".equals(endpoint.getScheme());
    if ((!tls && !(p.allowInsecureLdap() && "ldap".equals(endpoint.getScheme())))
        || endpoint.getHost() == null
        || endpoint.getUserInfo() != null
        || endpoint.getQuery() != null
        || endpoint.getFragment() != null) {
      throw new IllegalArgumentException(
          "One LDAPS endpoint is required; plaintext LDAP is local-development only");
    }
  }

  private DirContext connect(String dn, String password) throws NamingException {
    if (password == null || password.isBlank()) throw new javax.naming.AuthenticationException();
    var env = new Hashtable<String, String>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, p.ldapUrl());
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, dn);
    env.put(Context.SECURITY_CREDENTIALS, password);
    env.put(Context.REFERRAL, "throw");
    env.put("com.sun.jndi.ldap.connect.timeout", "2000");
    env.put("com.sun.jndi.ldap.read.timeout", "3000");
    return new InitialDirContext(env);
  }

  public DirectoryIdentity authenticate(String username, String password) {
    try {
      var user = lookup(username);
      var ctx = connect(user.dn(), password);
      ctx.close();
      return user.identity();
    } catch (javax.naming.AuthenticationException ex) {
      throw denied();
    } catch (NamingException ex) {
      throw new AuthenticationServiceException("Directory unavailable", ex);
    }
  }

  public DirectoryIdentity resolve(String username) {
    return lookup(username).identity();
  }

  private User lookup(String username) {
    if (username == null || !username.matches("[A-Za-z0-9._-]{1,64}")) throw denied();
    DirContext ctx = null;
    try {
      ctx = connect(p.bindDn(), p.bindPassword());
      var c = new SearchControls();
      c.setSearchScope(SearchControls.SUBTREE_SCOPE);
      c.setCountLimit(2);
      c.setTimeLimit(3000);
      c.setReturningAttributes(new String[] {"uid"});
      var users =
          ctx.search(
              "ou=people," + p.baseDn(),
              "(&(objectClass=inetOrgPerson)(uid=" + LdapEncoder.filterEncode(username) + "))",
              c);
      String dn;
      String canonicalUsername;
      try {
        if (!users.hasMore()) throw denied();
        var entry = users.next();
        dn = entry.getNameInNamespace();
        var uid = entry.getAttributes().get("uid");
        if (uid == null || uid.size() != 1) throw denied();
        canonicalUsername = uid.get().toString();
        if (!canonicalUsername.matches("[A-Za-z0-9._-]{1,64}")) throw denied();
        if (users.hasMore()) throw denied();
      } finally {
        users.close();
      }
      c.setCountLimit(50);
      c.setReturningAttributes(new String[] {"cn"});
      var groups =
          ctx.search(
              "ou=groups," + p.baseDn(),
              "(&(objectClass=groupOfNames)(member=" + LdapEncoder.filterEncode(dn) + "))",
              c);
      var roles = new TreeSet<String>();
      try {
        while (groups.hasMore()) {
          var group = new LdapName(groups.next().getNameInNamespace());
          if (group.equals(new LdapName("cn=sentinel-users,ou=groups," + p.baseDn())))
            roles.add("ROLE_USER");
          if (group.equals(new LdapName("cn=sentinel-admins,ou=groups," + p.baseDn())))
            roles.add("ROLE_ADMIN");
        }
      } finally {
        groups.close();
      }
      // No role is granted merely because a user exists in the directory.
      return new User(dn, new DirectoryIdentity(canonicalUsername, List.copyOf(roles)));
    } catch (NamingException ex) {
      throw new AuthenticationServiceException("Directory unavailable", ex);
    } finally {
      if (ctx != null)
        try {
          ctx.close();
        } catch (NamingException ignored) {
        }
    }
  }

  public void checkAvailability() {
    DirContext ctx = null;
    try {
      ctx = connect(p.bindDn(), p.bindPassword());
      ctx.getAttributes(p.baseDn(), new String[] {"objectClass"});
    } catch (NamingException ex) {
      throw new AuthenticationServiceException("Directory unavailable", ex);
    } finally {
      if (ctx != null)
        try {
          ctx.close();
        } catch (NamingException ignored) {
        }
    }
  }

  private BadCredentialsException denied() {
    return new BadCredentialsException("Authentication failed");
  }

  private record User(String dn, DirectoryIdentity identity) {}
}
