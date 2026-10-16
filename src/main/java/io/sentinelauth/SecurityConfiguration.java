package io.sentinelauth;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.*;

@Configuration
public class SecurityConfiguration {
  @Bean
  SecurityContextRepository contextRepository() {
    return new HttpSessionSecurityContextRepository();
  }

  @Bean
  SecurityFilterChain security(HttpSecurity http, SecurityContextRepository repository)
      throws Exception {
    http.addFilterBefore(
        new SessionLifetimeFilter(),
        org.springframework.security.web.access.intercept.AuthorizationFilter.class);
    http.securityContext(c -> c.securityContextRepository(repository).requireExplicitSave(true))
        .authorizeHttpRequests(
            a ->
                a.requestMatchers("/api/auth/csrf", "/api/auth/ldap", "/api/auth/kerberos")
                    .permitAll()
                    .requestMatchers("/actuator/health/**", "/actuator/prometheus")
                    .permitAll()
                    .requestMatchers("/api/admin/**")
                    .hasRole("ADMIN")
                    .requestMatchers("/api/me", "/api/resource")
                    .hasRole("USER")
                    .anyRequest()
                    .denyAll())
        .sessionManagement(s -> s.sessionFixation(f -> f.changeSessionId()))
        .requestCache(c -> c.disable())
        .exceptionHandling(
            e ->
                e.authenticationEntryPoint(
                        (q, s, x) -> {
                          s.setStatus(401);
                          s.setContentType("application/json");
                          s.getWriter().write("{\"error\":\"unauthorized\"}");
                        })
                    .accessDeniedHandler(
                        (q, s, x) -> {
                          s.setStatus(403);
                          s.setContentType("application/json");
                          s.getWriter().write("{\"error\":\"forbidden\"}");
                        }))
        .logout(
            l ->
                l.logoutUrl("/api/auth/logout")
                    .invalidateHttpSession(true)
                    .deleteCookies("SESSION")
                    .logoutSuccessHandler((q, s, a) -> s.setStatus(204)))
        .headers(
            h ->
                h.contentSecurityPolicy(
                    c -> c.policyDirectives("default-src 'none'; frame-ancestors 'none'")));
    return http.build();
  }
}
