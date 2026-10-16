package io.sentinelauth;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
public record DirectoryIdentity(String username, List<String> roles) {
 public java.util.List<SimpleGrantedAuthority> authorities() {
  return roles.stream().map(SimpleGrantedAuthority::new).toList();
 }
}
