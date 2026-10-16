package io.sentinelauth;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Absolute lifetime bounds stale directory roles even when a session remains active. */
final class SessionLifetimeFilter extends OncePerRequestFilter {
  private static final long MAX_AGE_MILLIS = java.time.Duration.ofHours(8).toMillis();

  @Override
  protected void doFilterInternal(HttpServletRequest q, HttpServletResponse s, FilterChain chain)
      throws ServletException, IOException {
    var session = q.getSession(false);
    if (session != null
        && System.currentTimeMillis() - session.getCreationTime() > MAX_AGE_MILLIS) {
      session.invalidate();
      SecurityContextHolder.clearContext();
      s.setStatus(401);
      s.setContentType("application/json");
      s.getWriter().write("{\"error\":\"session_expired\"}");
      return;
    }
    chain.doFilter(q, s);
  }
}
