package io.sentinelauth;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;

// Isolated failure-policy tests; IdentityProtocolsIT verifies the actual authentication providers.
class AuthenticationFailurePolicyTest {
  final LdapDirectory directory = mock(LdapDirectory.class);
  final AuditTrail audit = mock(AuditTrail.class);
  final SecurityContextRepository repository = mock(SecurityContextRepository.class);
  final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
  final AuthController controller =
      new AuthController(
          directory,
          mock(KerberosAcceptor.class),
          audit,
          metrics,
          ObservationRegistry.create(),
          new AttemptLimiter(),
          repository);
  final MockHttpServletRequest request = new MockHttpServletRequest();
  final MockHttpServletResponse response = new MockHttpServletResponse();

  @AfterEach
  void clearContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void successfulCredentialsCannotCreateSessionWhenAuditWriteFails() {
    when(directory.authenticate("alice", "password"))
        .thenReturn(new DirectoryIdentity("alice", List.of("ROLE_USER")));
    doThrow(new DataAccessResourceFailureException("offline"))
        .when(audit)
        .record(anyString(), anyString(), anyString(), anyString());
    var result = controller.ldap("alice", "password", request, response);
    assertThat(result.getStatusCode().value()).isEqualTo(503);
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verifyNoInteractions(repository);
    assertThat(
            metrics.get("sentinel.auth.attempts").tag("outcome", "unavailable").counter().count())
        .isEqualTo(1);
  }

  @Test
  void badCredentialsInvalidatePreviousSession() {
    var session = (org.springframework.mock.web.MockHttpSession) request.getSession();
    when(directory.authenticate("alice", "wrong"))
        .thenThrow(new BadCredentialsException("private details"));
    var result = controller.ldap("alice", "wrong", request, response);
    assertThat(result.getStatusCode().value()).isEqualTo(401);
    assertThat(result.getBody().toString()).doesNotContain("private details");
    assertThat(session.isInvalid()).isTrue();
    verifyNoInteractions(repository);
  }

  @Test
  void directoryOutageDoesNotCreateSession() {
    when(directory.authenticate("alice", "password"))
        .thenThrow(new AuthenticationServiceException("offline"));
    assertThat(controller.ldap("alice", "password", request, response).getStatusCode().value())
        .isEqualTo(503);
    verifyNoInteractions(repository);
  }

  @Test
  void failureAuditOutageReturnsUnavailable() {
    when(directory.authenticate("alice", "wrong")).thenThrow(new BadCredentialsException("bad"));
    doThrow(new DataAccessResourceFailureException("offline"))
        .when(audit)
        .record(anyString(), anyString(), anyString(), anyString());
    assertThat(controller.ldap("alice", "wrong", request, response).getStatusCode().value())
        .isEqualTo(503);
    assertThat(
            metrics.get("sentinel.auth.attempts").tag("outcome", "unavailable").counter().count())
        .isEqualTo(1);
    verifyNoInteractions(repository);
  }
}
