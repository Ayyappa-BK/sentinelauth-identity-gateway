package io.sentinelauth;

import com.github.benmanes.caffeine.cache.*;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;

@Component
public class AttemptLimiter {
  private final Cache<String, AtomicInteger> attempts =
      Caffeine.newBuilder().maximumSize(10000).expireAfterWrite(Duration.ofMinutes(1)).build();

  public boolean allow(String ip) {
    return attempts.get(ip, k -> new AtomicInteger()).incrementAndGet() <= 20;
  }
}
