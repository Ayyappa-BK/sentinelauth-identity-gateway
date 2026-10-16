package io.sentinelauth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

// Isolated route-policy tests. Real credential validation is exercised in GatewayIT.
@WebMvcTest(ApiController.class)
@org.springframework.test.context.ContextConfiguration(
    classes = {ApiController.class, SecurityConfiguration.class})
class SecurityPolicyTest {
  @Autowired MockMvc mvc;

  @Test
  void anonymousDenied() throws Exception {
    mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
  }

  @Test
  void csrfRequiredBeforeCredentialProcessing() throws Exception {
    mvc.perform(post("/api/auth/ldap").param("username", "alice").param("password", "bad"))
        .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(roles = "USER")
  void userCannotAccessAdmin() throws Exception {
    mvc.perform(get("/api/admin/status")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void adminAllowed() throws Exception {
    mvc.perform(get("/api/admin/status")).andExpect(status().isOk());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void unknownRoutesDenied() throws Exception {
    mvc.perform(get("/api/unknown")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(roles = {})
  void authenticatedWithoutGroupDenied() throws Exception {
    mvc.perform(get("/api/me")).andExpect(status().isForbidden());
  }
}
