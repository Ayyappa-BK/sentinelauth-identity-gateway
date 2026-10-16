package io.sentinelauth;

import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class ApiController {
  @GetMapping("/api/me")
  public Map<String, Object> me(Authentication a) {
    return Map.of(
        "username",
        a.getName(),
        "roles",
        a.getAuthorities().stream().map(Object::toString).toList());
  }

  @GetMapping("/api/resource")
  public Map<String, String> resource() {
    return Map.of("message", "Authorized enterprise resource");
  }

  @GetMapping("/api/admin/status")
  public Map<String, String> admin() {
    return Map.of("status", "authorized");
  }
}
