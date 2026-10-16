package io.sentinelauth;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class IdentityPolicyTest {
  @Test
  void mapsExactRealm() {
    assertThat(KerberosAcceptor.mapPrincipal("alice@SENTINEL.TEST", "SENTINEL.TEST"))
        .isEqualTo("alice");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "alice@EVIL.TEST",
        "HTTP/gateway@SENTINEL.TEST",
        "alice@evil@SENTINEL.TEST",
        "@SENTINEL.TEST",
        "alice\n@SENTINEL.TEST"
      })
  void rejectsAmbiguousPrincipals(String value) {
    assertThatThrownBy(() -> KerberosAcceptor.mapPrincipal(value, "SENTINEL.TEST"))
        .isInstanceOf(org.springframework.security.authentication.BadCredentialsException.class);
  }

  @Test
  void enforcesBoundedRateLimit() {
    var limiter = new AttemptLimiter();
    for (int i = 0; i < 20; i++) assertThat(limiter.allow("127.0.0.1")).isTrue();
    assertThat(limiter.allow("127.0.0.1")).isFalse();
    assertThat(limiter.allow("127.0.0.2")).isTrue();
  }

  @Test
  void rejectsPlaintextOutsideLocal() {
    var p =
        new IdentityProperties(
            "ldap://example:389",
            "dc=test",
            "uid=reader",
            "secret",
            "REALM",
            "HTTP/gateway",
            "/keytab",
            false);
    assertThatThrownBy(() -> new LdapDirectory(p)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void absoluteSessionExpiryClearsContext() throws Exception {
    var q = new org.springframework.mock.web.MockHttpServletRequest();
    var session =
        new org.springframework.mock.web.MockHttpSession() {
          @Override
          public long getCreationTime() {
            return System.currentTimeMillis() - java.time.Duration.ofHours(9).toMillis();
          }
        };
    q.setSession(session);
    var response = new org.springframework.mock.web.MockHttpServletResponse();
    var chain = new org.springframework.mock.web.MockFilterChain();
    new SessionLifetimeFilter().doFilter(q, response, chain);
    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(session.isInvalid()).isTrue();
    assertThat(chain.getRequest()).isNull();
  }

  @Test
  void noImplicitRoles() {
    assertThat(new DirectoryIdentity("alice", java.util.List.of()).authorities()).isEmpty();
  }
}
