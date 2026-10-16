package io.sentinelauth;

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.Callable;
import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import org.ietf.jgss.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "sentinel.integration", matches = "true")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class GatewayIT {
  static final String base = System.getenv().getOrDefault("TEST_BASE_URL", "http://localhost:8080");
  static final Path secrets = Path.of(System.getenv().getOrDefault("TEST_SECRET_DIR", ".secrets"));
  static final ObjectMapper json = new ObjectMapper();

  static String password(String name) throws Exception {
    return Files.readString(secrets.resolve(name + "_password")).strip();
  }

  static class Browser {
    final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
    final HttpClient http =
        HttpClient.newBuilder()
            .cookieHandler(cookies)
            .connectTimeout(java.time.Duration.ofSeconds(5))
            .build();
    String csrf;

    HttpResponse<String> get(String path) throws Exception {
      return http.send(
          HttpRequest.newBuilder(URI.create(base + path))
              .timeout(java.time.Duration.ofSeconds(10))
              .GET()
              .build(),
          HttpResponse.BodyHandlers.ofString());
    }

    void csrf() throws Exception {
      var r = get("/api/auth/csrf");
      assertThat(r.statusCode()).isEqualTo(200);
      csrf = json.readTree(r.body()).get("token").asText();
    }

    HttpResponse<String> post(String path, String body, String auth) throws Exception {
      var b =
          HttpRequest.newBuilder(URI.create(base + path))
              .timeout(java.time.Duration.ofSeconds(10))
              .header("X-CSRF-TOKEN", csrf)
              .header("Content-Type", "application/x-www-form-urlencoded");
      if (auth != null) b.header("Authorization", auth);
      return http.send(
          b.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
          HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> ldap(String user, String pass) throws Exception {
      csrf();
      return post(
          "/api/auth/ldap",
          "username="
              + URLEncoder.encode(user, java.nio.charset.StandardCharsets.UTF_8)
              + "&password="
              + URLEncoder.encode(pass, java.nio.charset.StandardCharsets.UTF_8),
          null);
    }

    String session() {
      return cookies.getCookieStore().getCookies().stream()
          .filter(c -> c.getName().equals("SESSION"))
          .map(HttpCookie::getValue)
          .findFirst()
          .orElse("");
    }
  }

  @Test
  @Order(1)
  void ldapAndSessionRotation() throws Exception {
    var b = new Browser();
    b.csrf();
    String old = b.session();
    assertThat(old).isNotBlank();
    var r = b.post("/api/auth/ldap", "username=alice&password=" + password("alice"), null);
    assertThat(r.statusCode()).isEqualTo(200);
    assertThat(r.body()).contains("ROLE_USER").doesNotContain("ROLE_ADMIN");
    assertThat(b.session()).isNotEqualTo(old);
    assertThat(b.get("/api/me").statusCode()).isEqualTo(200);
    assertThat(b.get("/api/admin/status").statusCode()).isEqualTo(403);
    var stale = new Browser();
    stale.cookies.getCookieStore().add(URI.create(base), new HttpCookie("SESSION", old));
    assertThat(stale.get("/api/me").statusCode()).isEqualTo(401);
    b.csrf();
    assertThat(b.post("/api/auth/logout", "", null).statusCode()).isEqualTo(204);
    assertThat(b.get("/api/me").statusCode()).isEqualTo(401);
  }

  @Test
  @Order(2)
  void ldapFailureDoesNotEnumerate() throws Exception {
    var wrong = new Browser().ldap("alice", "incorrect");
    var unknown = new Browser().ldap("nobody", "incorrect");
    assertThat(wrong.statusCode()).isEqualTo(401);
    assertThat(unknown.statusCode()).isEqualTo(401);
    assertThat(wrong.body()).isEqualTo(unknown.body());
  }

  @Test
  @Order(3)
  void emptyPasswordAndFilterInjectionDenied() throws Exception {
    assertThat(new Browser().ldap("alice", "").statusCode()).isEqualTo(401);
    assertThat(new Browser().ldap("*)(uid=*)", password("alice")).statusCode()).isEqualTo(401);
  }

  @Test
  @Order(4)
  void explicitAdminRole() throws Exception {
    var b = new Browser();
    assertThat(b.ldap("bob", password("bob")).statusCode()).isEqualTo(200);
    assertThat(b.get("/api/admin/status").statusCode()).isEqualTo(200);
  }

  @Test
  @Order(5)
  void leastPrivilegeIdentity() throws Exception {
    var b = new Browser();
    var r = b.ldap("unprivileged", password("alice"));
    assertThat(r.statusCode()).isEqualTo(200);
    assertThat(r.body()).contains("\"roles\":[]");
    assertThat(b.get("/api/me").statusCode()).isEqualTo(403);
  }

  @Test
  @Order(6)
  void csrfAndAnonymousAccessDenied() throws Exception {
    var b = new Browser();
    assertThat(b.get("/api/me").statusCode()).isEqualTo(401);
    var r =
        b.http.send(
            HttpRequest.newBuilder(URI.create(base + "/api/auth/ldap"))
                .POST(HttpRequest.BodyPublishers.ofString("username=alice&password=bad"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertThat(r.statusCode()).isEqualTo(403);
  }

  @Test
  @Order(7)
  void invalidNegotiateTokensDenied() throws Exception {
    for (String token : List.of("Negotiate !!!", "Negotiate YWJj", "Basic YWJj")) {
      var b = new Browser();
      b.csrf();
      var r = b.post("/api/auth/kerberos", "", token);
      assertThat(r.statusCode()).isEqualTo(401);
      assertThat(r.headers().firstValue("WWW-Authenticate")).contains("Negotiate");
    }
  }

  static LoginContext login(String pw) throws Exception {
    var options =
        Map.<String, Object>of(
            "useTicketCache",
            "false",
            "doNotPrompt",
            "false",
            "principal",
            "alice@SENTINEL.TEST",
            "isInitiator",
            "true",
            "refreshKrb5Config",
            "true");
    var config =
        new Configuration() {
          public AppConfigurationEntry[] getAppConfigurationEntry(String n) {
            return new AppConfigurationEntry[] {
              new AppConfigurationEntry(
                  "com.sun.security.auth.module.Krb5LoginModule",
                  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                  options)
            };
          }
        };
    var login =
        new LoginContext(
            "client",
            null,
            callbacks -> {
              for (var c : callbacks) {
                if (c instanceof NameCallback n) n.setName("alice@SENTINEL.TEST");
                else if (c instanceof PasswordCallback p) p.setPassword(pw.toCharArray());
                else throw new UnsupportedCallbackException(c);
              }
            },
            config);
    login.login();
    return login;
  }

  @Test
  @Order(8)
  void realKerberosMutualAuthenticationAndReplayRejection() throws Exception {
    var login = login(password("alice"));
    try {
      Subject.callAs(
          login.getSubject(),
          (Callable<Void>)
              () -> {
                var manager = GSSManager.getInstance();
                var name = manager.createName("HTTP@gateway", GSSName.NT_HOSTBASED_SERVICE);
                var context =
                    manager.createContext(
                        name, new Oid("1.3.6.1.5.5.2"), null, GSSContext.DEFAULT_LIFETIME);
                try {
                  context.requestMutualAuth(true);
                  context.requestCredDeleg(false);
                  var token = context.initSecContext(new byte[0], 0, 0);
                  String header = "Negotiate " + Base64.getEncoder().encodeToString(token);
                  var b = new Browser();
                  b.csrf();
                  var result = b.post("/api/auth/kerberos", "", header);
                  assertThat(result.statusCode()).describedAs(result.body()).isEqualTo(200);
                  assertThat(result.body()).contains("alice", "ROLE_USER");
                  var reply =
                      Base64.getDecoder()
                          .decode(
                              result
                                  .headers()
                                  .firstValue("WWW-Authenticate")
                                  .orElseThrow()
                                  .substring(10));
                  context.initSecContext(reply, 0, reply.length);
                  assertThat(context.isEstablished()).isTrue();
                  assertThat(context.getMutualAuthState()).isTrue();
                  assertThat(b.get("/api/me").statusCode()).isEqualTo(200);
                  var replay = new Browser();
                  replay.csrf();
                  assertThat(replay.post("/api/auth/kerberos", "", header).statusCode())
                      .isEqualTo(401);
                } finally {
                  context.dispose();
                }
                return null;
              });
    } finally {
      login.logout();
    }
  }

  @Test
  @Order(9)
  void kdcRejectsWrongPassword() {
    assertThatThrownBy(() -> login("incorrect")).isInstanceOf(LoginException.class);
  }

  @Test
  @Order(10)
  void metricsIncludeBothProtocols() throws Exception {
    var url = System.getenv().getOrDefault("TEST_MANAGEMENT_URL", "http://localhost:9090");
    var r =
        HttpClient.newHttpClient()
            .send(
                HttpRequest.newBuilder(URI.create(url + "/actuator/prometheus")).build(),
                HttpResponse.BodyHandlers.ofString());
    assertThat(r.statusCode()).isEqualTo(200);
    assertThat(r.body())
        .contains(
            "sentinel_auth_attempts_total",
            "method=\"ldap\"",
            "method=\"kerberos\"",
            "outcome=\"success\"",
            "outcome=\"failure\"",
            "sentinel_auth_latency_seconds");
  }
}
